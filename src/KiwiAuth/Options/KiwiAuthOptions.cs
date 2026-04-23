namespace KiwiAuth.Options;

public class KiwiAuthOptions
{
    public JwtOptions Jwt { get; set; } = new();
    public RefreshTokenOptions RefreshToken { get; set; } = new();
    public MfaOptions Mfa { get; set; } = new();
    public GoogleOptions Google { get; set; } = new();
    public FrontendOptions Frontend { get; set; } = new();
    public PasswordPolicyOptions Password { get; set; } = new();
    public LockoutOptions Lockout { get; set; } = new();
    public EmailOptions Email { get; set; } = new();
}

public class JwtOptions
{
    public string Issuer { get; set; } = "KiwiAuth";
    public string Audience { get; set; } = "KiwiAuth";
    public string SigningKey { get; set; } = string.Empty;
    public int AccessTokenMinutes { get; set; } = 15;
}

public class RefreshTokenOptions
{
    public int DaysToLive { get; set; } = 7;

    // Two near-simultaneous refresh calls can legitimately arrive with the same
    // raw token (multi-tab SPA, retried mobile request, etc.). Inside this
    // window we treat a "rotated token replay" as a race, not as theft —
    // the second caller gets 401 token_recently_rotated, but the family is NOT
    // revoked. Longer windows trade security for tolerance to flaky networks.
    public int GraceWindowSeconds { get; set; } = 30;
}

public class MfaOptions
{
    // Lifetime of the interim MFA session token issued after password verification.
    // The user must complete TOTP within this window.
    public int SessionTokenMinutes { get; set; } = 5;

    // Number of recovery codes generated when MFA is first enabled.
    public int RecoveryCodeCount { get; set; } = 8;
}

public class GoogleOptions
{
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;

    public bool Enabled =>
        !string.IsNullOrWhiteSpace(ClientId) &&
        !string.IsNullOrWhiteSpace(ClientSecret);
}

public class FrontendOptions
{
    public string GoogleSuccessRedirectUrl { get; set; } = "/";
    public string GoogleErrorRedirectUrl { get; set; } = "/";

    // Frontend page that receives userId + token query params and calls GET /auth/confirm-email.
    public string EmailConfirmationUrl { get; set; } = "/auth/confirm-email";

    // Frontend page that shows the reset form and calls POST /auth/reset-password.
    public string PasswordResetUrl { get; set; } = "/auth/reset-password";
}

public class PasswordPolicyOptions
{
    public int RequiredLength { get; set; } = 8;
    public bool RequireDigit { get; set; } = true;
    public bool RequireUppercase { get; set; } = false;
    public bool RequireNonAlphanumeric { get; set; } = false;
}

public class LockoutOptions
{
    public bool Enabled { get; set; } = true;
    public int MaxFailedAttempts { get; set; } = 5;
    public int LockoutMinutes { get; set; } = 15;
}

public class EmailOptions
{
    // When true, users must confirm their email before they can log in.
    public bool RequireConfirmedEmail { get; set; } = false;
}
