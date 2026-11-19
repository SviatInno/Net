using FEDept.BackendCourse.GroupA1.Api.Template.Email;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure;
using FEDept.BackendCourse.GroupA1.Api.Template.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Authentication;

public static class AuthenticationServiceCollectionExtensions
{
    /// <summary>
    /// Login, email challenge, refresh, logout and the access check. Requires
    /// <c>AddFrontendSecurity</c> (cookie SameSite policy) and <c>AddApiRateLimiting</c>.
    /// </summary>
    public static IServiceCollection AddAuthenticationFeature(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<AuthKeysOptions>()
            .Configure<IConfiguration>(AuthKeysOptions.Bind)
            .ValidateOnStart();
        services.AddSingleton<IValidateOptions<AuthKeysOptions>, AuthKeysOptionsValidator>();

        services.AddOptions<LoginOptions>()
            .Configure<IConfiguration>(LoginOptions.Bind)
            .ValidateOnStart();
        services.AddSingleton<IValidateOptions<LoginOptions>, LoginOptionsValidator>();

        services.AddOptions<SmtpOptions>().Bind(configuration.GetSection(SmtpOptions.SectionName));
        services.TryAddSingleton<IPasswordHasher, Argon2PasswordHasher>();
        services.TryAddSingleton<IEmailSender, SmtpEmailSender>();

        services.AddSingleton<DummyPasswordHash>();
        services.AddSingleton<LoginSecrets>();
        services.AddSingleton<AuditIdentifiers>();
        services.AddSingleton<LoginFailureLimiter>();
        services.AddSingleton<TokenService>();
        services.AddSingleton<AuthCookies>();
        services.AddScoped<LoginService>();
        services.AddScoped<SessionService>();

        // No default authenticate scheme: the token (and the user status in the database) is checked
        // only for endpoints that require authorization, not on every request.
        services.AddAuthentication(o =>
            {
                o.DefaultChallengeScheme = AccessCookieAuthenticationHandler.SchemeName;
                o.DefaultForbidScheme = AccessCookieAuthenticationHandler.SchemeName;
            })
            .AddScheme<AuthenticationSchemeOptions, AccessCookieAuthenticationHandler>(
                AccessCookieAuthenticationHandler.SchemeName, _ => { });

        services.AddAuthorizationBuilder()
            .SetDefaultPolicy(new AuthorizationPolicyBuilder(AccessCookieAuthenticationHandler.SchemeName)
                .RequireAuthenticatedUser()
                .Build());

        services.AddRateLimiter(limiter =>
        {
            limiter.AddPolicy(AuthenticationEndpoints.LoginRateLimitPolicy, http =>
                RateLimitingServiceCollectionExtensions.PerClientFixedWindow(
                    http, LoginOptions.LoginRequestsPerIpPerMinute, TimeSpan.FromMinutes(1)));
            limiter.AddPolicy(AuthenticationEndpoints.RefreshRateLimitPolicy, http =>
                RateLimitingServiceCollectionExtensions.PerClientFixedWindow(
                    http, LoginOptions.RefreshRequestsPerIpPerMinute, TimeSpan.FromMinutes(1)));
        });

        return services;
    }
}
