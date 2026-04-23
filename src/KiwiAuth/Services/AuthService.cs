using KiwiAuth.Data;
using KiwiAuth.Models;
using KiwiAuth.Options;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace KiwiAuth.Services;

public class AuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly KiwiDbContext _db;
    private readonly TokenService _tokenService;
    private readonly KiwiAuthOptions _options;
    private readonly IEmailSender? _emailSender;
    private readonly IKiwiAuthEventSink _eventSink;

    public AuthService(
        UserManager<ApplicationUser> userManager,
        KiwiDbContext db,
        TokenService tokenService,
        IOptions<KiwiAuthOptions> options,
        IKiwiAuthEventSink eventSink,
        IServiceProvider services)
    {
        _userManager = userManager;
        _db = db;
        _tokenService = tokenService;
        _options = options.Value;
        _eventSink = eventSink;
        _emailSender = services.GetService<IEmailSender>();
    }

    public async Task<(bool Success, string? ErrorCode, string? ErrorMessage, AuthResult? Result, bool EmailConfirmationRequired)> RegisterAsync(
        string email, string password, string? fullName, string ip)
    {
        if (await _userManager.FindByEmailAsync(email) is not null)
            return (false, "email_taken", "An account with this email already exists.", null, false);

        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            FullName = fullName,
        };

        var createResult = await _userManager.CreateAsync(user, password);
        if (!createResult.Succeeded)
        {
            var error = createResult.Errors.FirstOrDefault();
            return (false, "registration_failed", error?.Description ?? "Registration failed.", null, false);
        }

        await _userManager.AddToRoleAsync(user, "User");

        if (_emailSender is not null)
        {
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var encodedToken = Uri.EscapeDataString(token);
            var confirmUrl = $"{_options.Frontend.EmailConfirmationUrl}?userId={user.Id}&token={encodedToken}";

            await _emailSender.SendAsync(
                email,
                "Confirm your email",
                $"<p>Please confirm your email address by clicking the link below:</p>" +
                $"<p><a href=\"{confirmUrl}\">Confirm Email</a></p>");
        }

        if (_options.Email.RequireConfirmedEmail)
            return (true, null, null, null, true);

        return (true, null, null, await IssueTokensAsync(user, ip), false);
    }

    public async Task<(bool Success, string? ErrorCode, string? ErrorMessage, LoginResult? Result)> LoginAsync(
        string email, string password, string ip)
    {
        var user = await _userManager.FindByEmailAsync(email);

        // Deliberately vague error — do not reveal whether the email exists.
        if (user is null)
            return (false, "invalid_credentials", "Invalid email or password.", null);

        if (_options.Lockout.Enabled && await _userManager.IsLockedOutAsync(user))
            return (false, "account_locked", "Account is temporarily locked due to too many failed login attempts. Try again later.", null);

        if (!await _userManager.CheckPasswordAsync(user, password))
        {
            if (_options.Lockout.Enabled)
            {
                await _userManager.AccessFailedAsync(user);

                // Check if this attempt just triggered a lockout.
                if (await _userManager.IsLockedOutAsync(user))
                    return (false, "account_locked", "Too many failed attempts. Account is temporarily locked.", null);
            }

            return (false, "invalid_credentials", "Invalid email or password.", null);
        }

        if (_options.Lockout.Enabled)
            await _userManager.ResetAccessFailedCountAsync(user);

        if (_options.Email.RequireConfirmedEmail && !user.EmailConfirmed)
            return (false, "email_not_confirmed", "Please confirm your email address before signing in.", null);

        // If MFA is enabled: return a short-lived MFA session token.
        // The client must call POST /auth/mfa/verify to complete login.
        if (user.TwoFactorEnabled)
        {
            var mfaToken = _tokenService.GenerateMfaSessionToken(user);
            return (true, null, null, new LoginResult { RequiresMfa = true, MfaSessionToken = mfaToken });
        }

        var auth = await IssueTokensAsync(user, ip);
        return (true, null, null, new LoginResult
        {
            RequiresMfa = false,
            AccessToken = auth.AccessToken,
            RefreshToken = auth.RefreshToken,
            User = auth.User,
        });
    }

    public async Task<(bool Success, string? ErrorCode, string? ErrorMessage, AuthResult? Result)> RefreshAsync(
        string rawRefreshToken, string ip)
    {
        var tokenHash = _tokenService.HashToken(rawRefreshToken);

        var stored = await _db.RefreshTokens
            .Include(t => t.User)
            .FirstOrDefaultAsync(t => t.TokenHash == tokenHash);

        if (stored is null)
            return (false, "invalid_token", "Refresh token is invalid.", null);

        // ─── Reuse detection (OAuth 2.0 Security BCP §4.14) ─────────────────
        // A token that was rotated (replaced by another) but is being presented
        // again means either the legitimate client cached a stale copy OR the
        // token was stolen and the thief is racing the owner. We cannot tell
        // those apart, so we assume compromise and revoke the entire token
        // family. A short grace window absorbs the benign race case (multi-tab
        // SPA, retried mobile request) without false-flagging.
        if (stored.ReplacedByTokenHash is not null && stored.RevokedAtUtc.HasValue)
        {
            var graceWindow = TimeSpan.FromSeconds(_options.RefreshToken.GraceWindowSeconds);
            var withinGrace = stored.RevokedAtUtc.Value.Add(graceWindow) > DateTime.UtcNow;

            if (withinGrace)
                return (false, "token_recently_rotated",
                    "Refresh token was recently rotated; please use the latest one.", null);

            var revokedCount = await RevokeFamilyAsync(stored.FamilyId, ip,
                RefreshTokenRevocationReasons.ReuseDetected);
            await _db.SaveChangesAsync();

            var now = DateTime.UtcNow;
            await _eventSink.OnRefreshTokenReuseDetectedAsync(
                new RefreshTokenReuseEvent(stored.UserId, stored.FamilyId, ip, now));
            await _eventSink.OnFamilyRevokedAsync(
                new TokenFamilyRevokedEvent(stored.UserId, stored.FamilyId,
                    RefreshTokenRevocationReasons.ReuseDetected, revokedCount, now));

            return (false, "token_reuse_detected",
                "Session invalidated because a rotated refresh token was replayed.", null);
        }

        if (!stored.IsActive)
            return (false, "token_expired_or_revoked", "Refresh token has expired or been revoked.", null);

        // Rotation: revoke the old token, issue a fresh one on the same family.
        var (newRaw, newHash) = _tokenService.GenerateRefreshToken();

        stored.RevokedAtUtc = DateTime.UtcNow;
        stored.RevokedByIp = ip;
        stored.ReplacedByTokenHash = newHash;
        stored.ReasonRevoked = RefreshTokenRevocationReasons.Rotated;

        _db.RefreshTokens.Add(new RefreshToken
        {
            UserId = stored.UserId,
            TokenHash = newHash,
            FamilyId = stored.FamilyId,
            ExpiresAtUtc = DateTime.UtcNow.AddDays(_options.RefreshToken.DaysToLive),
            CreatedAtUtc = DateTime.UtcNow,
            CreatedByIp = ip,
        });

        await _db.SaveChangesAsync();

        var roles = await _userManager.GetRolesAsync(stored.User);
        var accessToken = _tokenService.GenerateAccessToken(stored.User, roles);

        return (true, null, null, new AuthResult
        {
            AccessToken = accessToken,
            RefreshToken = newRaw,
            User = MapUser(stored.User, roles),
        });
    }

    /// <summary>
    /// Revokes every still-active token in a family. Called on reuse detection
    /// and available for future "sign out everywhere" admin actions.
    /// Caller is responsible for SaveChangesAsync.
    /// </summary>
    private async Task<int> RevokeFamilyAsync(Guid familyId, string ip, string reason)
    {
        var familyMembers = await _db.RefreshTokens
            .Where(t => t.FamilyId == familyId && t.RevokedAtUtc == null)
            .ToListAsync();

        var now = DateTime.UtcNow;
        foreach (var member in familyMembers)
        {
            member.RevokedAtUtc = now;
            member.RevokedByIp = ip;
            member.ReasonRevoked = reason;
        }

        return familyMembers.Count;
    }

    public async Task<bool> LogoutAsync(string rawRefreshToken, string ip)
    {
        var tokenHash = _tokenService.HashToken(rawRefreshToken);
        var stored = await _db.RefreshTokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash);

        if (stored is null || !stored.IsActive)
            return false;

        stored.RevokedAtUtc = DateTime.UtcNow;
        stored.RevokedByIp = ip;
        stored.ReasonRevoked = RefreshTokenRevocationReasons.Logout;
        await _db.SaveChangesAsync();

        return true;
    }

    public async Task<(bool Success, string? ErrorCode, string? ErrorMessage)> ConfirmEmailAsync(
        string userId, string token)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
            return (false, "invalid_token", "Email confirmation link is invalid.");

        var result = await _userManager.ConfirmEmailAsync(user, token);
        if (!result.Succeeded)
            return (false, "invalid_token", "Email confirmation link is invalid or has expired.");

        return (true, null, null);
    }

    public async Task ForgotPasswordAsync(string email)
    {
        // Always succeed silently — never reveal whether the email exists.
        if (_emailSender is null)
            return;

        var user = await _userManager.FindByEmailAsync(email);
        if (user is null || !user.EmailConfirmed)
            return;

        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var encodedToken = Uri.EscapeDataString(token);
        var resetUrl = $"{_options.Frontend.PasswordResetUrl}?userId={user.Id}&token={encodedToken}";

        await _emailSender.SendAsync(
            email,
            "Reset your password",
            $"<p>Reset your password by clicking the link below:</p>" +
            $"<p><a href=\"{resetUrl}\">Reset Password</a></p>" +
            $"<p>If you didn't request this, you can safely ignore this email.</p>");
    }

    public async Task<(bool Success, string? ErrorCode, string? ErrorMessage)> ResetPasswordAsync(
        string userId, string token, string newPassword)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
            return (false, "invalid_token", "Password reset link is invalid.");

        var result = await _userManager.ResetPasswordAsync(user, token, newPassword);
        if (!result.Succeeded)
        {
            var error = result.Errors.FirstOrDefault();
            return (false, "reset_failed", error?.Description ?? "Password reset failed.");
        }

        return (true, null, null);
    }

    /// <summary>
    /// Issues a new access token and refresh token for a given user.
    /// Used by login, registration, and the Google OAuth callback.
    /// </summary>
    public async Task<AuthResult> IssueTokensAsync(ApplicationUser user, string ip)
    {
        var roles = await _userManager.GetRolesAsync(user);
        var accessToken = _tokenService.GenerateAccessToken(user, roles);
        var (rawToken, tokenHash) = _tokenService.GenerateRefreshToken();

        _db.RefreshTokens.Add(new RefreshToken
        {
            UserId = user.Id,
            TokenHash = tokenHash,
            FamilyId = Guid.NewGuid(),
            ExpiresAtUtc = DateTime.UtcNow.AddDays(_options.RefreshToken.DaysToLive),
            CreatedAtUtc = DateTime.UtcNow,
            CreatedByIp = ip,
        });

        await _db.SaveChangesAsync();

        return new AuthResult
        {
            AccessToken = accessToken,
            RefreshToken = rawToken,
            User = MapUser(user, roles),
        };
    }

    private static UserInfo MapUser(ApplicationUser user, IList<string> roles) => new()
    {
        Id = user.Id,
        Email = user.Email!,
        FullName = user.FullName,
        Roles = [.. roles],
    };
}
