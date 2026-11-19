using Microsoft.Extensions.Options;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Authentication;

/// <summary>
/// Signing and HMAC keys plus JWT issuer/audience. Read from flat configuration keys
/// (environment variables of the same name). Every key is base64 of at least 32 random bytes;
/// a missing, malformed, short or shared key stops the application at startup.
/// </summary>
public sealed class AuthKeysOptions
{
    public const int MinKeyBytes = 32;

    public const string JwtAccessSecretKey = "JWT_ACCESS_SECRET";
    public const string JwtRefreshSecretKey = "JWT_REFRESH_SECRET";
    public const string LoginChallengeHmacKeyKey = "LOGIN_CHALLENGE_HMAC_KEY";
    public const string AuditHmacKeyKey = "AUDIT_LOG_HMAC_KEY";
    public const string JwtIssuerKey = "JWT_ISSUER";
    public const string JwtAudienceKey = "JWT_AUDIENCE";

    public byte[] JwtAccessSecret { get; set; } = [];

    public byte[] JwtRefreshSecret { get; set; } = [];

    /// <summary>HMAC-SHA256 key for login codes and magic link secrets.</summary>
    public byte[] LoginChallengeHmacKey { get; set; } = [];

    /// <summary>HMAC-SHA256 key for pseudonymous audit identifiers of unknown emails.</summary>
    public byte[] AuditHmacKey { get; set; } = [];

    public string JwtIssuer { get; set; } = string.Empty;

    public string JwtAudience { get; set; } = string.Empty;

    internal static void Bind(AuthKeysOptions options, IConfiguration configuration)
    {
        options.JwtAccessSecret = DecodeKey(configuration[JwtAccessSecretKey]);
        options.JwtRefreshSecret = DecodeKey(configuration[JwtRefreshSecretKey]);
        options.LoginChallengeHmacKey = DecodeKey(configuration[LoginChallengeHmacKeyKey]);
        options.AuditHmacKey = DecodeKey(configuration[AuditHmacKeyKey]);
        options.JwtIssuer = configuration[JwtIssuerKey]?.Trim() ?? string.Empty;
        options.JwtAudience = configuration[JwtAudienceKey]?.Trim() ?? string.Empty;
    }

    /// <returns>The decoded key, or an empty array when the value is missing or not base64.</returns>
    private static byte[] DecodeKey(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return [];
        }

        var buffer = new byte[value.Length];
        return Convert.TryFromBase64String(value.Trim(), buffer, out var written) ? buffer[..written] : [];
    }
}

internal sealed class AuthKeysOptionsValidator : IValidateOptions<AuthKeysOptions>
{
    public ValidateOptionsResult Validate(string? name, AuthKeysOptions options)
    {
        var keys = new (string Name, byte[] Value)[]
        {
            (AuthKeysOptions.JwtAccessSecretKey, options.JwtAccessSecret),
            (AuthKeysOptions.JwtRefreshSecretKey, options.JwtRefreshSecret),
            (AuthKeysOptions.LoginChallengeHmacKeyKey, options.LoginChallengeHmacKey),
            (AuthKeysOptions.AuditHmacKeyKey, options.AuditHmacKey),
        };

        // Messages name the setting, never its value.
        var errors = new List<string>();
        foreach (var (keyName, value) in keys)
        {
            if (value.Length < AuthKeysOptions.MinKeyBytes)
            {
                errors.Add($"{keyName} is required: base64 of at least {AuthKeysOptions.MinKeyBytes} random bytes (openssl rand -base64 32).");
            }
        }

        for (var i = 0; i < keys.Length; i++)
        {
            for (var j = i + 1; j < keys.Length; j++)
            {
                if (keys[i].Value.Length > 0 && keys[i].Value.AsSpan().SequenceEqual(keys[j].Value))
                {
                    errors.Add($"{keys[i].Name} and {keys[j].Name} must be different keys.");
                }
            }
        }

        if (options.JwtIssuer.Length == 0)
        {
            errors.Add($"{AuthKeysOptions.JwtIssuerKey} is required.");
        }

        if (options.JwtAudience.Length == 0)
        {
            errors.Add($"{AuthKeysOptions.JwtAudienceKey} is required.");
        }

        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }
}
