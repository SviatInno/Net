using System.Threading.RateLimiting;
using FEDept.BackendCourse.GroupA1.Api.Template.Email;
using FEDept.BackendCourse.GroupA1.Api.Template.Security;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Registration;

public static class RegistrationServiceCollectionExtensions
{
    public static IServiceCollection AddRegistration(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<RegistrationOptions>()
            .Bind(configuration.GetSection(RegistrationOptions.SectionName))
            .Validate(
                o => o.HasValidHmacKey(),
                $"{RegistrationOptions.SectionName}:HmacKey must be base64 of at least {RegistrationOptions.MinKeyBytes} bytes.")
            .Validate(
                o => o.ConfirmationMethod != ConfirmationMethod.MagicLink
                    || Uri.TryCreate(o.MagicLinkUrl, UriKind.Absolute, out _),
                $"{RegistrationOptions.SectionName}:MagicLinkUrl must be an absolute URL.")
            .Validate(
                o => o.RegisterRateLimit is { PermitLimit: > 0, WindowSeconds: > 0 }
                    && o.ResendRateLimit is { PermitLimit: > 0, WindowSeconds: > 0 },
                "Registration rate limits must be positive.")
            .ValidateOnStart();

        services.AddOptions<SmtpOptions>().Bind(configuration.GetSection(SmtpOptions.SectionName));

        services.AddSingleton<IPasswordHasher, Argon2PasswordHasher>();
        services.AddSingleton<ChallengeSecrets>();
        services.AddSingleton<IEmailSender, SmtpEmailSender>();
        services.AddScoped<RegistrationService>();

        services.AddRateLimiter(limiter =>
        {
            limiter.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            limiter.AddPolicy(RegistrationEndpoints.RegisterRateLimitPolicy, http =>
                PerClientFixedWindow(http, o => o.RegisterRateLimit));
            limiter.AddPolicy(RegistrationEndpoints.ResendRateLimitPolicy, http =>
                PerClientFixedWindow(http, o => o.ResendRateLimit));
            limiter.OnRejected = async (context, cancellationToken) =>
            {
                if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
                {
                    context.HttpContext.Response.Headers.RetryAfter =
                        ((int)Math.Ceiling(retryAfter.TotalSeconds)).ToString(System.Globalization.CultureInfo.InvariantCulture);
                }

                var problemDetails = context.HttpContext.RequestServices.GetRequiredService<IProblemDetailsService>();
                var problem = new ProblemDetails
                {
                    Status = StatusCodes.Status429TooManyRequests,
                    Title = "Too many requests",
                    Detail = "Request rate limit exceeded. Try again later.",
                };
                problem.Extensions["code"] = "rate_limited";
                await problemDetails.WriteAsync(new ProblemDetailsContext
                {
                    HttpContext = context.HttpContext,
                    ProblemDetails = problem,
                });
            };
        });

        return services;
    }

    private static RateLimitPartition<string> PerClientFixedWindow(
        HttpContext http, Func<RegistrationOptions, FixedWindowLimit> select)
    {
        var limit = select(http.RequestServices.GetRequiredService<IOptions<RegistrationOptions>>().Value);
        var client = http.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        return RateLimitPartition.GetFixedWindowLimiter(client, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = limit.PermitLimit,
            Window = TimeSpan.FromSeconds(limit.WindowSeconds),
            QueueLimit = 0,
        });
    }
}
