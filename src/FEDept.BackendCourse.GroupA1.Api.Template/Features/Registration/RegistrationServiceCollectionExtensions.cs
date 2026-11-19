using System.Threading.RateLimiting;
using FEDept.BackendCourse.GroupA1.Api.Template.Email;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure;
using FEDept.BackendCourse.GroupA1.Api.Template.Security;
using Microsoft.Extensions.DependencyInjection.Extensions;
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

        // Shared with login: TryAdd keeps a single registration whichever feature runs first.
        services.TryAddSingleton<IPasswordHasher, Argon2PasswordHasher>();
        services.TryAddSingleton<IEmailSender, SmtpEmailSender>();
        services.AddSingleton<ChallengeSecrets>();
        services.AddScoped<RegistrationService>();

        // Rejection format (429 problem + Retry-After) is shared: see AddApiRateLimiting.
        services.AddRateLimiter(limiter =>
        {
            limiter.AddPolicy(RegistrationEndpoints.RegisterRateLimitPolicy, http =>
                PerClientFixedWindow(http, o => o.RegisterRateLimit));
            limiter.AddPolicy(RegistrationEndpoints.ResendRateLimitPolicy, http =>
                PerClientFixedWindow(http, o => o.ResendRateLimit));
        });

        return services;
    }

    private static RateLimitPartition<string> PerClientFixedWindow(
        HttpContext http, Func<RegistrationOptions, FixedWindowLimit> select)
    {
        var limit = select(http.RequestServices.GetRequiredService<IOptions<RegistrationOptions>>().Value);
        return RateLimitingServiceCollectionExtensions.PerClientFixedWindow(
            http, limit.PermitLimit, TimeSpan.FromSeconds(limit.WindowSeconds));
    }
}
