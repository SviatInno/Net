using System.Buffers.Text;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Registration;

/// <summary>Generates email secrets and computes / compares their HMAC-SHA256.</summary>
public sealed class ChallengeSecrets(IOptions<RegistrationOptions> options)
{
    public const int OtpLength = 6;
    public const int TokenBytes = 32;

    private readonly byte[] _key = options.Value.GetHmacKeyBytes();

    public static string NewSecret(ConfirmationMethod method) => method switch
    {
        ConfirmationMethod.Otp => RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6", CultureInfo.InvariantCulture),
        _ => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(TokenBytes)),
    };

    public static bool IsWellFormedCode(string code) =>
        code.Length == OtpLength && code.All(char.IsAsciiDigit);

    public static bool IsWellFormedToken(string token) =>
        token.Length <= 64
        && Base64Url.IsValid(token, out var decodedLength)
        && decodedLength == TokenBytes;

    // The method prefix separates the two secret domains.
    public byte[] Hash(ConfirmationMethod method, string secret) =>
        HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes($"{method}:{secret}"));

    public bool Matches(byte[] storedHash, ConfirmationMethod method, string secret) =>
        CryptographicOperations.FixedTimeEquals(storedHash, Hash(method, secret));
}
