namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Authentication;

/// <summary>
/// Audit events of section 1.5. <c>subject</c> is a user id or, for an unknown email, a keyed
/// pseudonym (<see cref="AuditIdentifiers"/>). The request id comes from the logging scope.
/// By design no event takes an email, password, hash, code, link token, HMAC, JWT, cookie or key,
/// and failures log only the exception type: SMTP and driver messages can quote addresses or hosts.
/// </summary>
internal static partial class AuthenticationLog
{
    [LoggerMessage(EventId = 2000, Level = LogLevel.Information,
        Message = "Login succeeded: user {UserId}, mode {Mode}")]
    public static partial void LoginSucceeded(this ILogger logger, Guid userId, string mode);

    [LoggerMessage(EventId = 2001, Level = LogLevel.Warning,
        Message = "Login failed: subject {Subject}, reason {Reason}")]
    public static partial void LoginFailed(this ILogger logger, string subject, string reason);

    [LoggerMessage(EventId = 2002, Level = LogLevel.Warning,
        Message = "Login rate limited: subject {Subject}, limit {Limit}")]
    public static partial void LoginRateLimited(this ILogger logger, string subject, string limit);

    [LoggerMessage(EventId = 2003, Level = LogLevel.Error,
        Message = "Login failed: user {UserId}, attempt transaction not committed ({ExceptionType})")]
    public static partial void ChallengeNotSaved(this ILogger logger, Guid userId, string exceptionType);

    [LoggerMessage(EventId = 2010, Level = LogLevel.Information,
        Message = "Login challenge created: user {UserId}, attempt {AttemptId}, method {Method}")]
    public static partial void ChallengeCreated(this ILogger logger, Guid userId, Guid attemptId, string method);

    [LoggerMessage(EventId = 2011, Level = LogLevel.Information,
        Message = "Login challenge email sent: user {UserId}, attempt {AttemptId}, method {Method}")]
    public static partial void ChallengeEmailSent(this ILogger logger, Guid userId, Guid attemptId, string method);

    [LoggerMessage(EventId = 2012, Level = LogLevel.Error,
        Message = "Login challenge email failed: user {UserId}, attempt {AttemptId}, method {Method} ({ExceptionType})")]
    public static partial void ChallengeEmailFailed(this ILogger logger, Guid userId, Guid attemptId, string method, string exceptionType);

    [LoggerMessage(EventId = 2013, Level = LogLevel.Information,
        Message = "Login challenge resent: user {UserId}, attempt {AttemptId}, method {Method}")]
    public static partial void ChallengeResent(this ILogger logger, Guid userId, Guid attemptId, string method);

    [LoggerMessage(EventId = 2014, Level = LogLevel.Information,
        Message = "Login challenge confirmed: user {UserId}, attempt {AttemptId}, method {Method}")]
    public static partial void ChallengeConfirmed(this ILogger logger, Guid userId, Guid attemptId, string method);

    [LoggerMessage(EventId = 2015, Level = LogLevel.Warning,
        Message = "Login challenge rejected: user {UserId}, attempt {AttemptId}, operation {Operation}, reason {Reason}")]
    public static partial void ChallengeRejected(this ILogger logger, Guid? userId, Guid? attemptId, string operation, string reason);

    [LoggerMessage(EventId = 2020, Level = LogLevel.Information,
        Message = "Refresh succeeded: user {UserId}")]
    public static partial void RefreshSucceeded(this ILogger logger, Guid userId);

    [LoggerMessage(EventId = 2021, Level = LogLevel.Warning,
        Message = "Refresh rejected: user {UserId}, reason {Reason}")]
    public static partial void RefreshRejected(this ILogger logger, Guid? userId, string reason);

    [LoggerMessage(EventId = 2030, Level = LogLevel.Information,
        Message = "Logout: cookies cleared")]
    public static partial void LoggedOut(this ILogger logger);

    [LoggerMessage(EventId = 2040, Level = LogLevel.Warning,
        Message = "Access rejected: user {UserId}, reason {Reason}")]
    public static partial void AccessRejected(this ILogger logger, Guid? userId, string reason);

    [LoggerMessage(EventId = 2050, Level = LogLevel.Error,
        Message = "Token signing failed: user {UserId} ({ExceptionType})")]
    public static partial void TokenIssueFailed(this ILogger logger, Guid userId, string exceptionType);
}
