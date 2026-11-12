using FEDept.BackendCourse.GroupA1.Api.Template.Email;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Registration;

internal static class RegistrationEmails
{
    public static EmailMessage Create(string to, ConfirmationMethod method, string secret, string magicLinkUrl)
    {
        var ttlMinutes = (int)RegistrationOptions.ChallengeTtl.TotalMinutes;
        if (method == ConfirmationMethod.Otp)
        {
            return new EmailMessage(
                to,
                "Your registration code",
                $"""
                Your registration confirmation code: {secret}

                The code expires in {ttlMinutes} minutes. If you did not register, ignore this email.
                """);
        }

        var separator = magicLinkUrl.Contains('?') ? '&' : '?';
        var link = $"{magicLinkUrl}{separator}token={Uri.EscapeDataString(secret)}";
        return new EmailMessage(
            to,
            "Confirm your registration",
            $"""
            Open the link and press "Confirm" to activate your account:
            {link}

            The link expires in {ttlMinutes} minutes and can be used once.
            If you did not register, ignore this email.
            """);
    }
}
