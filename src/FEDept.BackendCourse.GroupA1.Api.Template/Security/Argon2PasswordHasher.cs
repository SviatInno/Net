using Isopoh.Cryptography.Argon2;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Security;

/// <summary>
/// Argon2id with the OWASP baseline parameters (m=19 MiB, t=2, p=1).
/// Produces a PHC string like <c>$argon2id$v=19$m=19456,t=2,p=1$&lt;salt&gt;$&lt;hash&gt;</c>.
/// </summary>
public sealed class Argon2PasswordHasher : IPasswordHasher
{
    private const int TimeCost = 2;
    private const int MemoryCostKib = 19 * 1024;
    private const int Parallelism = 1;
    private const int HashLength = 32;

    public string Hash(string password) =>
        Argon2.Hash(password, TimeCost, MemoryCostKib, Parallelism, Argon2Type.HybridAddressing, HashLength);

    public bool Verify(string password, string encodedHash) => Argon2.Verify(encodedHash, password);
}
