using System.Buffers.Text;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Authentication;

/// <summary>Generates login email secrets and computes / compares their HMAC-SHA256 (LOGIN_CHALLENGE_HMAC_KEY).</summary>
public sealed class LoginSecrets(IOptions<AuthKeysOptions> options)
{
    public const int OtpLength = 6;
    public const int TokenSecretBytes = 32;

    private static readonly int TokenSecretLength = Base64Url.GetEncodedLength(TokenSecretBytes);

    private readonly byte[] _key = options.Value.LoginChallengeHmacKey;

    public static string NewSecret(LoginChallengeMethod method) => method switch
    {
        LoginChallengeMethod.Otp => RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6", CultureInfo.InvariantCulture),
        _ => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(TokenSecretBytes)),
    };

    public static bool IsWellFormedCode(string code) => code.Length == OtpLength && code.All(char.IsAsciiDigit);

    /// <summary>Magic link token: <c>attemptId.secret</c>.</summary>
    public static string FormatToken(Guid attemptId, string secret) =>
        $"{attemptId.ToString("D", CultureInfo.InvariantCulture)}.{secret}";

    public static bool TryParseToken(string token, out Guid attemptId, out string secret)
    {
        attemptId = Guid.Empty;
        secret = string.Empty;
        var dot = token.IndexOf('.', StringComparison.Ordinal);
        if (dot <= 0 || !Guid.TryParseExact(token.AsSpan(0, dot), "D", out attemptId))
        {
            return false;
        }

        secret = token[(dot + 1)..];
        return secret.Length == TokenSecretLength
            && Base64Url.IsValid(secret, out var decodedLength)
            && decodedLength == TokenSecretBytes;
    }

    // The prefix separates login secrets from any other HMAC use and the two methods from each other.
    public byte[] Hash(LoginChallengeMethod method, string secret) =>
        HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes($"login:{LoginChallengeMethods.ToName(method)}:{secret}"));

    public bool Matches(byte[] storedHash, LoginChallengeMethod method, string secret) =>
        CryptographicOperations.FixedTimeEquals(storedHash, Hash(method, secret));
}
