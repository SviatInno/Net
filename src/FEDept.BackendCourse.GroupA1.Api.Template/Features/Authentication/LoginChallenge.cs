using System.Text.Json.Serialization;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Authentication;

/// <summary>
/// The second login step (email challenge). Only HMAC-SHA256 of the code or link secret is stored.
/// A user has at most one unconsumed attempt (partial unique index on <c>user_id</c>).
/// Rows are changed only under <c>SELECT ... FOR UPDATE</c>: the user row first, then the attempt.
/// </summary>
public sealed class LoginChallenge
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    /// <summary>Fixed at creation: resend and configuration changes never switch it.</summary>
    public LoginChallengeMethod Method { get; set; }

    public required byte[] SecretHash { get; set; }

    /// <summary>Wrong code entries since the last send. Magic links do not count.</summary>
    public int Attempts { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>Start of the TTL and of the resend cooldown.</summary>
    public DateTimeOffset LastSentAt { get; set; }

    public DateTimeOffset? ConsumedAt { get; set; }

    public LoginChallengeConsumedReason? ConsumedReason { get; set; }

    public DateTimeOffset ExpiresAt => LastSentAt + LoginOptions.ChallengeTtl;

    public DateTimeOffset ResendAllowedAt => LastSentAt + LoginOptions.ResendCooldown;

    public static LoginChallenge Create(Guid id, Guid userId, LoginChallengeMethod method, byte[] secretHash, DateTimeOffset now) => new()
    {
        Id = id,
        UserId = userId,
        Method = method,
        SecretHash = secretHash,
        CreatedAt = now,
        LastSentAt = now,
    };

    /// <summary>Replaces the secret (the old one stops working), restarts TTL and cooldown, resets attempts.</summary>
    public void Reissue(byte[] secretHash, DateTimeOffset now)
    {
        SecretHash = secretHash;
        LastSentAt = now;
        Attempts = 0;
    }

    public void Consume(LoginChallengeConsumedReason reason, DateTimeOffset now)
    {
        ConsumedAt = now;
        ConsumedReason = reason;
    }
}

[JsonConverter(typeof(JsonStringEnumConverter<LoginChallengeMethod>))]
public enum LoginChallengeMethod
{
    [JsonStringEnumMemberName("otp")]
    Otp,

    [JsonStringEnumMemberName("magic_link")]
    MagicLink,
}

public enum LoginChallengeConsumedReason
{
    Confirmed,
    AttemptsExhausted,
    Replaced,
    UserInactive,
}

/// <summary>Wire / database names (also the configuration values).</summary>
public static class LoginChallengeMethods
{
    public static string ToName(LoginChallengeMethod method) => method == LoginChallengeMethod.MagicLink ? "magic_link" : "otp";

    public static LoginChallengeMethod FromName(string name) =>
        TryParse(name, out var method) ? method : throw new ArgumentOutOfRangeException(nameof(name), name, "Unknown method.");

    public static bool TryParse(string name, out LoginChallengeMethod method)
    {
        switch (name.ToLowerInvariant())
        {
            case "otp":
                method = LoginChallengeMethod.Otp;
                return true;
            case "magic_link":
                method = LoginChallengeMethod.MagicLink;
                return true;
            default:
                method = default;
                return false;
        }
    }

    public static string ReasonName(LoginChallengeConsumedReason reason) => reason switch
    {
        LoginChallengeConsumedReason.Confirmed => "confirmed",
        LoginChallengeConsumedReason.AttemptsExhausted => "attempts_exhausted",
        LoginChallengeConsumedReason.Replaced => "replaced",
        LoginChallengeConsumedReason.UserInactive => "user_inactive",
        _ => throw new ArgumentOutOfRangeException(nameof(reason), reason, null),
    };

    public static LoginChallengeConsumedReason ReasonFromName(string name) => name switch
    {
        "confirmed" => LoginChallengeConsumedReason.Confirmed,
        "attempts_exhausted" => LoginChallengeConsumedReason.AttemptsExhausted,
        "replaced" => LoginChallengeConsumedReason.Replaced,
        "user_inactive" => LoginChallengeConsumedReason.UserInactive,
        _ => throw new ArgumentOutOfRangeException(nameof(name), name, "Unknown reason."),
    };
}
