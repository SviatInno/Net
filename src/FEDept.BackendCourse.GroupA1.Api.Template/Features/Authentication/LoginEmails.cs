using FEDept.BackendCourse.GroupA1.Api.Template.Email;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Authentication;

internal static class LoginEmails
{
    public static EmailMessage Create(string to, LoginChallenge challenge, string secret, string magicLinkUrl)
    {
        var ttlMinutes = (int)LoginOptions.ChallengeTtl.TotalMinutes;
        if (challenge.Method == LoginChallengeMethod.Otp)
        {
            return new EmailMessage(
                to,
                "Your sign-in code",
                $"""
                Your sign-in code: {secret}

                The code expires in {ttlMinutes} minutes. If you did not try to sign in, ignore this email
                and consider changing your password.
                """);
        }

        // The token travels in the URL fragment: browsers do not send it to any server or in Referer.
        var link = $"{magicLinkUrl}#token={LoginSecrets.FormatToken(challenge.Id, secret)}";
        return new EmailMessage(
            to,
            "Sign in to your account",
            $"""
            Open the link and press "Sign in" to finish signing in:
            {link}

            The link expires in {ttlMinutes} minutes and can be used once.
            If you did not try to sign in, ignore this email and consider changing your password.
            """);
    }
}
