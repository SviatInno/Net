using System.Net.Mail;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Users;

/// <summary>
/// The single email normalization and format rule. Registration stores and login looks up
/// <see cref="Normalize"/>d values, so both must use this class.
/// </summary>
public static class UserEmail
{
    public const int MaxLength = 254;

    public static string Normalize(string email) => email.Trim().ToLowerInvariant();

    /// <returns>An error message, or <c>null</c> when the normalized email is valid.</returns>
    public static string? Validate(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return "Email is required.";
        }

        return IsValid(Normalize(email)) ? null : "Email has an invalid format.";
    }

    private static bool IsValid(string email)
    {
        if (email.Length > MaxLength || email.Any(char.IsWhiteSpace))
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
