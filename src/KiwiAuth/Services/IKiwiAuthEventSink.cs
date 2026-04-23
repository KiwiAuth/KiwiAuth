namespace KiwiAuth.Services;

/// <summary>
/// Optional observability hook for security-relevant auth events.
/// Register your own implementation in DI to forward these to Seq / Slack /
/// SIEM / a paged on-call engineer. KiwiAuth ships with a no-op default so
/// consumers who don't care pay nothing.
/// </summary>
public interface IKiwiAuthEventSink
{
    /// <summary>
    /// Fired when a caller presents a refresh token that was already rotated
    /// out. This is how KiwiAuth detects that a stolen token is in circulation.
    /// By the time this fires, the full token family has already been revoked.
    /// </summary>
    Task OnRefreshTokenReuseDetectedAsync(RefreshTokenReuseEvent evt, CancellationToken ct = default);

    /// <summary>
    /// Fired whenever KiwiAuth revokes an entire token family (currently only
    /// on reuse detection, but future "admin revoke all sessions" flows will
    /// use the same path).
    /// </summary>
    Task OnFamilyRevokedAsync(TokenFamilyRevokedEvent evt, CancellationToken ct = default);
}

public sealed record RefreshTokenReuseEvent(
    string UserId,
    Guid FamilyId,
    string? Ip,
    DateTime DetectedAtUtc);

public sealed record TokenFamilyRevokedEvent(
    string UserId,
    Guid FamilyId,
    string Reason,
    int TokensRevoked,
    DateTime RevokedAtUtc);

/// <summary>Default no-op sink. Replaced by user-supplied implementation if any.</summary>
internal sealed class NullKiwiAuthEventSink : IKiwiAuthEventSink
{
    public Task OnRefreshTokenReuseDetectedAsync(RefreshTokenReuseEvent evt, CancellationToken ct = default)
        => Task.CompletedTask;

    public Task OnFamilyRevokedAsync(TokenFamilyRevokedEvent evt, CancellationToken ct = default)
        => Task.CompletedTask;
}
