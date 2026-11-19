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

/// <summary>Only <see cref="Active"/> users may sign in or use a token.</summary>
public enum UserStatus
{
    Pending,
    Active,
    Blocked,
    Deleting,
    Deleted,
}

public static class UserStatusNames
{
    public static string ToName(UserStatus status) => status switch
    {
        UserStatus.Pending => "pending",
        UserStatus.Active => "active",
        UserStatus.Blocked => "blocked",
        UserStatus.Deleting => "deleting",
        UserStatus.Deleted => "deleted",
        _ => throw new ArgumentOutOfRangeException(nameof(status), status, null),
    };

    public static UserStatus FromName(string name) => name switch
    {
        "pending" => UserStatus.Pending,
        "active" => UserStatus.Active,
        "blocked" => UserStatus.Blocked,
        "deleting" => UserStatus.Deleting,
        "deleted" => UserStatus.Deleted,
        _ => throw new ArgumentOutOfRangeException(nameof(name), name, "Unknown user status."),
    };
}
