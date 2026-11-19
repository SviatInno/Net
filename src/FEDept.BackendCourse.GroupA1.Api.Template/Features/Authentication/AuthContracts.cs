namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Authentication;

public sealed record LoginRequest(string? Email, string? Password);

/// <summary>Either <c>attemptId</c> + <c>code</c> (OTP) or <c>token</c> = <c>attemptId.secret</c> (magic link).</summary>
public sealed record ConfirmLoginRequest(string? AttemptId, string? Code, string? Token);

public sealed record ResendLoginRequest(string? AttemptId);

/// <summary>202 from /auth/login: the email challenge was sent. Never contains the secret.</summary>
public sealed record LoginPendingResponse(
    bool ConfirmationRequired,
    LoginChallengeMethod Method,
    Guid AttemptId,
    int ExpiresInSeconds,
    int ResendAfterSeconds)
{
    public static LoginPendingResponse From(LoginChallenge challenge) => new(
        ConfirmationRequired: true,
        challenge.Method,
        challenge.Id,
        (int)LoginOptions.ChallengeTtl.TotalSeconds,
        (int)LoginOptions.ResendCooldown.TotalSeconds);
}

/// <summary>202 from /auth/login/resend.</summary>
public sealed record LoginResendResponse(
    LoginChallengeMethod Method,
    Guid AttemptId,
    int ExpiresInSeconds,
    int ResendAfterSeconds)
{
    public static LoginResendResponse From(LoginChallenge challenge) => new(
        challenge.Method,
        challenge.Id,
        (int)LoginOptions.ChallengeTtl.TotalSeconds,
        (int)LoginOptions.ResendCooldown.TotalSeconds);
}

/// <summary>200 from /auth/me: the verified user id only.</summary>
public sealed record CurrentUserResponse(Guid UserId);
