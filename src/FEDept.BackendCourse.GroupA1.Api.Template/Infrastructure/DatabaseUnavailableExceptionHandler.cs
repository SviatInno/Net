using Microsoft.AspNetCore.Diagnostics;
using Npgsql;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure;

/// <summary>
/// Turns "the database cannot be reached" into <c>503 service_unavailable</c> instead of 500,
/// so clients (and the access check) can tell an outage from an invalid request or session.
/// </summary>
public sealed partial class DatabaseUnavailableExceptionHandler(ILogger<DatabaseUnavailableExceptionHandler> logger)
    : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        if (!IsDatabaseUnavailable(exception))
        {
            return false;
        }

        DatabaseUnavailable(logger, exception.GetType().Name);
        await WriteAsync(httpContext);
        return true;
    }

    public static Task WriteAsync(HttpContext httpContext) => ProblemResponses.WriteAsync(
        httpContext,
        StatusCodes.Status503ServiceUnavailable,
        "service_unavailable",
        "Service unavailable",
        "A required service is temporarily unavailable. Try again later.");

    /// <summary>Connection-level failures only; SQL errors such as constraint violations stay 500.</summary>
    public static bool IsDatabaseUnavailable(Exception exception)
    {
        for (var current = exception; current is not null; current = current.InnerException)
        {
            switch (current)
            {
                case PostgresException postgres:
                    // 08: connection exception, 53: insufficient resources, 57P: operator intervention (shutdown).
                    return postgres.SqlState.StartsWith("08", StringComparison.Ordinal)
                        || postgres.SqlState.StartsWith("53", StringComparison.Ordinal)
                        || postgres.SqlState.StartsWith("57P", StringComparison.Ordinal);
                case NpgsqlException:
                case TimeoutException:
                    return true;
            }
        }

        return false;
    }

    // The exception text is not logged: it may contain connection details.
    [LoggerMessage(EventId = 910, Level = LogLevel.Error, Message = "Database unavailable: {ExceptionType}")]
    private static partial void DatabaseUnavailable(ILogger logger, string exceptionType);
}
