using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure;

/// <summary>
/// Application-wide rate limiter settings: one rejection format for every policy.
/// Features only add their own named policies.
/// </summary>
public static partial class RateLimitingServiceCollectionExtensions
{
    public static IServiceCollection AddApiRateLimiting(this IServiceCollection services)
    {
        services.AddRateLimiter(limiter =>
        {
            limiter.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            limiter.OnRejected = async (context, _) =>
            {
                var http = context.HttpContext;
                var policy = http.GetEndpoint()?.Metadata.GetMetadata<EnableRateLimitingAttribute>()?.PolicyName ?? "unknown";
                http.RequestServices.GetRequiredService<ILoggerFactory>()
                    .CreateLogger("FEDept.BackendCourse.GroupA1.Api.Template.RateLimiting")
                    .RateLimitRejected(policy);

                TimeSpan? retryAfter = context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var delay) ? delay : null;
                await ProblemResponses.WriteAsync(
                    http,
                    StatusCodes.Status429TooManyRequests,
                    "rate_limited",
                    "Too many requests",
                    "Request rate limit exceeded. Try again later.",
                    retryAfter);
            };
        });

        return services;
    }

    /// <summary>A fixed window per client IP address.</summary>
    public static RateLimitPartition<string> PerClientFixedWindow(HttpContext http, int permitLimit, TimeSpan window) =>
        RateLimitPartition.GetFixedWindowLimiter(
            http.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = permitLimit,
                Window = window,
                QueueLimit = 0,
            });

    [LoggerMessage(EventId = 900, Level = LogLevel.Warning, Message = "Rate limit rejected a request: policy {Policy}")]
    private static partial void RateLimitRejected(this ILogger logger, string policy);
}
