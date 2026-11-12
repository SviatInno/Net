namespace FEDept.BackendCourse.GroupA1.Api.Template.Users;

public sealed class User
{
    public Guid Id { get; set; }

    /// <summary>Normalized email: trimmed and lower-cased. Unique.</summary>
    public required string Email { get; set; }

    /// <summary>Encoded slow hash (algorithm, parameters and salt are part of the string).</summary>
    public required string PasswordHash { get; set; }

    public UserStatus Status { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }
}

public enum UserStatus
{
    Pending,
    Active,
}
