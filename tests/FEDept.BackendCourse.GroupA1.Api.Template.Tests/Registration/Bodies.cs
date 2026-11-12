namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Registration;

public sealed record UserBody(Guid Id, string Email, string Status);

public sealed record PendingBody(bool ConfirmationRequired, string Method, Guid AttemptId, int ExpiresInSeconds, int ResendAfterSeconds);

public sealed record ProblemBody(int Status, string? Code, Dictionary<string, string[]>? Errors);
