using System.Text;
using FEDept.BackendCourse.GroupA1.Api.Template.Users;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Registration;

public static class RegistrationValidator
{
    public const int MaxEmailLength = UserEmail.MaxLength;
    public const int MinPasswordLength = 8;

    /// <summary>
    /// Argon2id has no input truncation, but an upper bound still keeps hashing cost predictable
    /// and the rule explicit: an over-long password is rejected, never silently cut.
    /// </summary>
    public const int MaxPasswordLength = 128;

    public static string NormalizeEmail(string email) => UserEmail.Normalize(email);

    /// <returns>An error message, or <c>null</c> when the normalized email is valid.</returns>
    public static string? ValidateEmail(string? email) => UserEmail.Validate(email);

    /// <returns>An error message, or <c>null</c> when the password satisfies the policy.</returns>
    public static string? ValidatePassword(string? password)
    {
        if (string.IsNullOrEmpty(password))
        {
            return "Password is required.";
        }

        // Count user-perceived code points, not UTF-16 units: "секрет12" has 8 characters.
        var length = 0;
        bool hasLetter = false, hasDigit = false;
        foreach (var rune in password.EnumerateRunes())
        {
            length++;
            hasLetter |= Rune.IsLetter(rune);
            hasDigit |= Rune.IsDigit(rune);
        }

        if (length < MinPasswordLength)
        {
            return $"Password must be at least {MinPasswordLength} characters long.";
        }

        if (length > MaxPasswordLength)
        {
            return $"Password must be at most {MaxPasswordLength} characters long.";
        }

        if (!hasLetter || !hasDigit)
        {
            return "Password must contain at least one letter and one digit.";
        }

        return null;
    }
}
