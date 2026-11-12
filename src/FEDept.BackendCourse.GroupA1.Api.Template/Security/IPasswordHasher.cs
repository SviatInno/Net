namespace FEDept.BackendCourse.GroupA1.Api.Template.Security;

public interface IPasswordHasher
{
    /// <summary>Returns an encoded slow hash with its own random salt embedded.</summary>
    string Hash(string password);

    bool Verify(string password, string encodedHash);
}
