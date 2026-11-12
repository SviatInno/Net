using System.Text.Json.Serialization;
using FEDept.BackendCourse.GroupA1.Api.Template.Users;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Registration;

/// <summary>
/// An email confirmation attempt for a pending user. The secret itself is never stored:
/// <see cref="SecretHash"/> is an HMAC-SHA256 of the code or link token.
/// </summary>
public sealed class RegistrationChallenge
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    public User User { get; set; } = null!;

    public ConfirmationMethod Method { get; set; }

    public required byte[] SecretHash { get; set; }

    /// <summary>
    /// Always <see cref="LastSentAt"/> + TTL. Stored on purpose (deliberate denormalization),
    /// so both fields must be updated together — see <see cref="Issue"/>.
    /// </summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>Number of wrong code entries.</summary>
    public int Attempts { get; set; }

    public DateTimeOffset LastSentAt { get; set; }

    /// <summary>Set on successful confirmation or on the last allowed wrong code entry.</summary>
    public DateTimeOffset? ConsumedAt { get; set; }

    /// <summary>Optimistic concurrency token: every modification must call <see cref="Touch"/>.</summary>
    public Guid Version { get; set; }

    public bool IsExhausted => ConsumedAt is not null && Attempts >= RegistrationOptions.MaxCodeAttempts;

    /// <summary>(Re)issues the challenge with a fresh secret: restarts TTL, resets attempts.</summary>
    public void Issue(byte[] secretHash, DateTimeOffset now)
    {
        SecretHash = secretHash;
        LastSentAt = now;
        ExpiresAt = now + RegistrationOptions.ChallengeTtl;
        Attempts = 0;
        ConsumedAt = null;
        Touch();
    }

    public void Touch() => Version = Guid.NewGuid();
}

[JsonConverter(typeof(JsonStringEnumConverter<ConfirmationMethod>))]
public enum ConfirmationMethod
{
    [JsonStringEnumMemberName("otp")]
    Otp,

    [JsonStringEnumMemberName("magic_link")]
    MagicLink,
}
