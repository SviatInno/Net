using System.Security.Cryptography;
using FEDept.BackendCourse.GroupA1.Api.Template.Security;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Authentication;

/// <summary>
/// A real hash of a random password, made once at startup. An unknown email is checked against it,
/// so the response time does not reveal whether an account exists.
/// </summary>
public sealed class DummyPasswordHash(IPasswordHasher passwordHasher)
{
    public string Value { get; } = passwordHasher.Hash(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
}
