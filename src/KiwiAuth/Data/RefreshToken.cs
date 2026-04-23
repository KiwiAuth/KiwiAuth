namespace KiwiAuth.Data;

public class RefreshToken
{
    public int Id { get; set; }

    public string UserId { get; set; } = string.Empty;
    public ApplicationUser User { get; set; } = null!;

    // Only the hash is stored — raw token is never persisted.
    public string TokenHash { get; set; } = string.Empty;

    // Shared by every refresh token derived from the same login (rotation chain).
    // A replayed-but-rotated token proves theft, so we revoke the whole family in one shot.
    public Guid FamilyId { get; set; }

    public DateTime ExpiresAtUtc { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public DateTime? RevokedAtUtc { get; set; }

    // Set on rotation to link old → new token in the chain.
    public string? ReplacedByTokenHash { get; set; }

    // "rotated" | "logout" | "reuse_detected" | "family_compromised" | null
    public string? ReasonRevoked { get; set; }

    public string? CreatedByIp { get; set; }
    public string? RevokedByIp { get; set; }

    public bool IsExpired => DateTime.UtcNow >= ExpiresAtUtc;
    public bool IsRevoked => RevokedAtUtc.HasValue;
    public bool IsActive => !IsRevoked && !IsExpired;
}

/// <summary>
/// Reasons a refresh token was revoked. Mirrors the string values persisted
/// on <see cref="RefreshToken.ReasonRevoked"/> so callers don't need to
/// hard-code magic strings when inspecting audit data.
/// </summary>
public static class RefreshTokenRevocationReasons
{
    public const string Rotated = "rotated";
    public const string Logout = "logout";
    public const string ReuseDetected = "reuse_detected";
    public const string FamilyCompromised = "family_compromised";
}
