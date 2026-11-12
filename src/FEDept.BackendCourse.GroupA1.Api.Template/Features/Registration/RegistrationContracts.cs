namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Registration;

public sealed record RegisterRequest(string? Email, string? Password);

/// <summary>Either <c>attemptId</c> + <c>code</c> (OTP) or <c>token</c> (magic link).</summary>
public sealed record ConfirmRegistrationRequest(Guid? AttemptId, string? Code, string? Token);

public sealed record ResendConfirmationRequest(string? Email);

/// <summary>201 on registration without confirmation, 200 on successful confirmation.</summary>
public sealed record RegisteredUserResponse(Guid Id, string Email, string Status);

/// <summary>202: the account waits for email confirmation. Never contains the secret.</summary>
public sealed record ConfirmationPendingResponse(
    bool ConfirmationRequired,
    ConfirmationMethod Method,
    Guid AttemptId,
    int ExpiresInSeconds,
    int ResendAfterSeconds)
{
    public static ConfirmationPendingResponse From(RegistrationChallenge challenge) => new(
        ConfirmationRequired: true,
        challenge.Method,
        challenge.Id,
        (int)RegistrationOptions.ChallengeTtl.TotalSeconds,
        (int)RegistrationOptions.ResendCooldown.TotalSeconds);
}
