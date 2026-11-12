namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Registration;

public sealed class RegistrationOptions
{
    public const string SectionName = "Registration";

    // Contract values (section 1.3.2); they are part of the API responses, so not configurable.
    public static readonly TimeSpan ChallengeTtl = TimeSpan.FromMinutes(10);
    public static readonly TimeSpan ResendCooldown = TimeSpan.FromSeconds(60);
    public const int MaxCodeAttempts = 5;
    public const int MinKeyBytes = 32;

    /// <summary>Scenario flag "registration": require email confirmation for new registrations.</summary>
    public bool ConfirmationEnabled { get; set; }

    /// <summary>Server-side choice of the confirmation method: Otp or MagicLink.</summary>
    public ConfirmationMethod ConfirmationMethod { get; set; } = ConfirmationMethod.Otp;

    /// <summary>Base64-encoded HMAC-SHA256 key (at least 32 bytes) for email secrets.</summary>
    public string HmacKey { get; set; } = string.Empty;

    /// <summary>Frontend page that receives <c>?token=...</c> and POSTs it to /auth/register/confirm.</summary>
    public string MagicLinkUrl { get; set; } = "http://localhost:5173/register/confirm";

    public FixedWindowLimit RegisterRateLimit { get; set; } = new() { PermitLimit = 10, WindowSeconds = 60 };

    public FixedWindowLimit ResendRateLimit { get; set; } = new() { PermitLimit = 10, WindowSeconds = 60 };

    public byte[] GetHmacKeyBytes() => Convert.FromBase64String(HmacKey);

    internal bool HasValidHmacKey()
    {
        var buffer = new byte[HmacKey.Length];
        return Convert.TryFromBase64String(HmacKey, buffer, out var written) && written >= MinKeyBytes;
    }
}

public sealed class FixedWindowLimit
{
    public int PermitLimit { get; set; }

    public int WindowSeconds { get; set; }
}
