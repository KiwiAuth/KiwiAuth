using KiwiAuth.Data;
using KiwiAuth.Services;
using KiwiAuth.Tests.TestHelpers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace KiwiAuth.Tests;

/// <summary>
/// Exercises refresh-token reuse detection (OAuth 2.0 Security BCP §4.14).
/// These tests talk to AuthService directly so they can inspect and manipulate
/// RefreshToken rows — simulating replay of a rotated token bypasses the
/// usual CookieContainer-driven HTTP flow.
/// </summary>
public class RefreshTokenReuseTests : IClassFixture<KiwiTestFactory>
{
    private readonly KiwiTestFactory _factory;

    public RefreshTokenReuseTests(KiwiTestFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Refresh_ReplayOfRotatedToken_RevokesEntireFamily()
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        var auth = scope.ServiceProvider.GetRequiredService<AuthService>();
        var db = scope.ServiceProvider.GetRequiredService<KiwiDbContext>();

        var email = UniqueEmail("reuse_family");
        var (_, _, _, registerResult, _) = await auth.RegisterAsync(email, "Test1234!", "Family Test", "127.0.0.1");
        var originalRefresh = registerResult!.RefreshToken;

        // Rotate once to produce a revoked "originalRefresh".
        var firstRefresh = await auth.RefreshAsync(originalRefresh, "127.0.0.1");
        Assert.True(firstRefresh.Success);

        // Push the rotated token outside the grace window so the next replay
        // is unambiguously reuse, not a race.
        await AgeOutGraceWindowAsync(db, originalRefresh, scope.ServiceProvider);

        // Replay the ORIGINAL token — classic stolen-token scenario.
        var replay = await auth.RefreshAsync(originalRefresh, "10.0.0.1");
        Assert.False(replay.Success);
        Assert.Equal("token_reuse_detected", replay.ErrorCode);

        var userId = await db.Users.Where(u => u.Email == email).Select(u => u.Id).SingleAsync();
        var tokens = await db.RefreshTokens.Where(t => t.UserId == userId).ToListAsync();

        // Every token in the family must now be revoked: the replayed one,
        // the intermediate that was already rotated, and the most recent one
        // that the legitimate client was still using.
        Assert.All(tokens, t => Assert.NotNull(t.RevokedAtUtc));

        // The newest one should carry the reuse reason (it was active until we caught the replay).
        var newest = tokens.OrderByDescending(t => t.CreatedAtUtc).First();
        Assert.Equal(RefreshTokenRevocationReasons.ReuseDetected, newest.ReasonRevoked);
    }

    [Fact]
    public async Task Refresh_ReplayWithinGraceWindow_DoesNotRevokeFamily()
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        var auth = scope.ServiceProvider.GetRequiredService<AuthService>();
        var db = scope.ServiceProvider.GetRequiredService<KiwiDbContext>();

        var email = UniqueEmail("reuse_grace");
        var (_, _, _, registerResult, _) = await auth.RegisterAsync(email, "Test1234!", "Grace Test", "127.0.0.1");
        var originalRefresh = registerResult!.RefreshToken;

        var firstRefresh = await auth.RefreshAsync(originalRefresh, "127.0.0.1");
        Assert.True(firstRefresh.Success);

        // Immediately replay the just-rotated token — classic SPA race with two tabs.
        var race = await auth.RefreshAsync(originalRefresh, "127.0.0.1");
        Assert.False(race.Success);
        Assert.Equal("token_recently_rotated", race.ErrorCode);

        // The family must still have one live token (the one firstRefresh issued).
        var userId = await db.Users.Where(u => u.Email == email).Select(u => u.Id).SingleAsync();
        var live = await db.RefreshTokens
            .Where(t => t.UserId == userId && t.RevokedAtUtc == null)
            .CountAsync();
        Assert.Equal(1, live);
    }

    [Fact]
    public async Task Refresh_ExpiredTokenNotPreviouslyRotated_DoesNotTriggerFamilyRevoke()
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        var auth = scope.ServiceProvider.GetRequiredService<AuthService>();
        var db = scope.ServiceProvider.GetRequiredService<KiwiDbContext>();

        var email = UniqueEmail("reuse_expired");
        var (_, _, _, registerResult, _) = await auth.RegisterAsync(email, "Test1234!", "Expired Test", "127.0.0.1");
        var originalRefresh = registerResult!.RefreshToken;

        // Fast-forward the token's expiry without rotating it — pure timeout scenario.
        var hash = scope.ServiceProvider.GetRequiredService<TokenService>().HashToken(originalRefresh);
        var row = await db.RefreshTokens.SingleAsync(t => t.TokenHash == hash);
        row.ExpiresAtUtc = DateTime.UtcNow.AddMinutes(-1);
        await db.SaveChangesAsync();

        var response = await auth.RefreshAsync(originalRefresh, "127.0.0.1");
        Assert.False(response.Success);
        Assert.Equal("token_expired_or_revoked", response.ErrorCode);

        // Family must NOT be touched — reason stays null (never actively revoked).
        var freshRow = await db.RefreshTokens.SingleAsync(t => t.TokenHash == hash);
        Assert.Null(freshRow.RevokedAtUtc);
        Assert.Null(freshRow.ReasonRevoked);
    }

    [Fact]
    public async Task Login_Twice_CreatesTwoSeparateFamilies()
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        var auth = scope.ServiceProvider.GetRequiredService<AuthService>();
        var db = scope.ServiceProvider.GetRequiredService<KiwiDbContext>();
        var tokens = scope.ServiceProvider.GetRequiredService<TokenService>();

        var email = UniqueEmail("reuse_two_families");
        await auth.RegisterAsync(email, "Test1234!", "Two Families", "127.0.0.1");

        // Second login issues another refresh token on a separate family.
        var second = await auth.LoginAsync(email, "Test1234!", "127.0.0.1");
        Assert.True(second.Success);
        var secondRefresh = second.Result!.RefreshToken!;

        var hashes = new[]
        {
            tokens.HashToken(secondRefresh),
        };

        var userId = await db.Users.Where(u => u.Email == email).Select(u => u.Id).SingleAsync();
        var rows = await db.RefreshTokens.Where(t => t.UserId == userId).ToListAsync();

        // Expect 2 tokens total (register + second login) in two different families.
        Assert.Equal(2, rows.Count);
        Assert.Equal(2, rows.Select(r => r.FamilyId).Distinct().Count());
    }

    [Fact]
    public async Task Logout_OnlyRevokesActiveToken_NotPreviouslyRotatedOnes()
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        var auth = scope.ServiceProvider.GetRequiredService<AuthService>();
        var db = scope.ServiceProvider.GetRequiredService<KiwiDbContext>();

        var email = UniqueEmail("reuse_logout");
        var (_, _, _, registerResult, _) = await auth.RegisterAsync(email, "Test1234!", "Logout Test", "127.0.0.1");
        var t1 = registerResult!.RefreshToken;

        var r1 = await auth.RefreshAsync(t1, "127.0.0.1");
        Assert.True(r1.Success);
        var t2 = r1.Result!.RefreshToken;

        await auth.LogoutAsync(t2, "127.0.0.1");

        var userId = await db.Users.Where(u => u.Email == email).Select(u => u.Id).SingleAsync();
        var rows = await db.RefreshTokens.Where(t => t.UserId == userId).ToListAsync();

        Assert.Equal(2, rows.Count);
        // The first token carries "rotated", the second "logout" — logout must not overwrite
        // the earlier rotation reason or touch its revocation timestamp.
        var rotated = rows.Single(r => r.ReasonRevoked == RefreshTokenRevocationReasons.Rotated);
        var loggedOut = rows.Single(r => r.ReasonRevoked == RefreshTokenRevocationReasons.Logout);
        Assert.NotEqual(rotated.RevokedAtUtc, loggedOut.RevokedAtUtc);
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private static string UniqueEmail(string prefix) =>
        $"{prefix}_{Guid.NewGuid():N}@example.com";

    /// <summary>
    /// Ages the revoked-at timestamp of the row that tracks <paramref name="rawToken"/>
    /// back by more than the configured grace window, so the next replay is detected
    /// as reuse rather than a concurrency race. Avoids Thread.Sleep in tests.
    /// </summary>
    private static async Task AgeOutGraceWindowAsync(KiwiDbContext db, string rawToken, IServiceProvider sp)
    {
        var hash = sp.GetRequiredService<TokenService>().HashToken(rawToken);
        var row = await db.RefreshTokens.SingleAsync(t => t.TokenHash == hash);
        row.RevokedAtUtc = row.RevokedAtUtc!.Value.AddMinutes(-5);
        await db.SaveChangesAsync();
    }
}
