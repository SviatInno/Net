using System.Net.Mail;
using System.Text;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Registration;

public static class RegistrationValidator
{
    public const int MaxEmailLength = 254;
    public const int MinPasswordLength = 8;

    /// <summary>
    /// Argon2id has no input truncation, but an upper bound still keeps hashing cost predictable
    /// and the rule explicit: an over-long password is rejected, never silently cut.
    /// </summary>
    public const int MaxPasswordLength = 128;

    public static string NormalizeEmail(string email) => email.Trim().ToLowerInvariant();

    /// <returns>An error message, or <c>null</c> when the normalized email is valid.</returns>
    public static string? ValidateEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return "Email is required.";
        }

        return IsValidEmail(NormalizeEmail(email)) ? null : "Email has an invalid format.";
    }

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

    private static bool IsValidEmail(string email)
    {
        if (email.Length > MaxEmailLength || email.Any(char.IsWhiteSpace))
        {
            return false;
        }

        // MailAddress also accepts "Name <a@b.c>"; require that the input is the bare address.
        if (!MailAddress.TryCreate(email, out var address)
            || address.Address != email
            || address.DisplayName.Length > 0)
        {
            return false;
        }

        var at = email.LastIndexOf('@');
        var local = email[..at];
        var domain = email[(at + 1)..];

        return local.Length is > 0 and <= 64
            && domain.Contains('.')
            && !domain.Contains("..")
            && !domain.StartsWith('.') && !domain.EndsWith('.')
            && !domain.StartsWith('-') && !domain.EndsWith('-');
    }
}
