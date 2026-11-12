namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Registration;

/// <summary>
/// Audit events of section 1.5. By design none of them takes the password, its hash,
/// the code, the link token or the request body.
/// </summary>
internal static partial class RegistrationLog
{
    [LoggerMessage(EventId = 1000, Level = LogLevel.Information,
        Message = "Registration succeeded: user {UserId}, status {Status}")]
    public static partial void RegistrationSucceeded(this ILogger logger, Guid userId, string status);

    [LoggerMessage(EventId = 1001, Level = LogLevel.Warning,
        Message = "Registration rejected: {Reason} ({Fields})")]
    public static partial void RegistrationRejected(this ILogger logger, string reason, string fields);

    [LoggerMessage(EventId = 1010, Level = LogLevel.Information,
        Message = "Confirmation email sent: attempt {AttemptId}, user {UserId}, method {Method}")]
    public static partial void ConfirmationEmailSent(this ILogger logger, Guid attemptId, Guid userId, ConfirmationMethod method);

    [LoggerMessage(EventId = 1011, Level = LogLevel.Error,
        Message = "Confirmation email failed: attempt {AttemptId}, user {UserId}, method {Method}")]
    public static partial void ConfirmationEmailFailed(this ILogger logger, Guid attemptId, Guid userId, ConfirmationMethod method, Exception exception);

    [LoggerMessage(EventId = 1020, Level = LogLevel.Information,
        Message = "Registration confirmed: attempt {AttemptId}, user {UserId}")]
    public static partial void ConfirmationSucceeded(this ILogger logger, Guid attemptId, Guid userId);

    [LoggerMessage(EventId = 1021, Level = LogLevel.Warning,
        Message = "Registration confirmation failed: attempt {AttemptId}, reason {Reason}")]
    public static partial void ConfirmationFailed(this ILogger logger, Guid? attemptId, string reason);

    [LoggerMessage(EventId = 1030, Level = LogLevel.Warning,
        Message = "Confirmation resend rejected: {Reason}")]
    public static partial void ResendRejected(this ILogger logger, string reason);
}
