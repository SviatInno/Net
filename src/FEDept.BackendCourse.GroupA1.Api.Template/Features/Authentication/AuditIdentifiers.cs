using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Authentication;

/// <summary>
/// Irreversible identifiers for audit logs: attacks on an unknown email can be correlated
/// without writing the address. Keyed (AUDIT_LOG_HMAC_KEY), so it cannot be brute-forced from a log.
/// </summary>
public sealed class AuditIdentifiers(IOptions<AuthKeysOptions> options)
{
    private readonly byte[] _key = options.Value.AuditHmacKey;

    /// <param name="normalizedEmail">The email after <see cref="Users.UserEmail.Normalize"/>.</param>
    public string ForEmail(string normalizedEmail) =>
        "email:" + Convert.ToHexStringLower(HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes(normalizedEmail)))[..24];
}
