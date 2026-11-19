using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.Extensions.Options;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Security;

public static class FrontendSecurityServiceCollectionExtensions
{
    /// <summary>Frontend origin settings, a credentialed CORS policy for it (if any) and CSRF protection.</summary>
    public static IServiceCollection AddFrontendSecurity(this IServiceCollection services)
    {
        services.AddOptions<FrontendOptions>()
            .Configure<IConfiguration>(FrontendOptions.Bind)
            .ValidateOnStart();
        services.AddSingleton<IValidateOptions<FrontendOptions>, FrontendOptionsValidator>();

        services.AddCors();
        services.AddOptions<CorsOptions>().Configure<IOptions<FrontendOptions>>((cors, frontend) =>
        {
            if (frontend.Value.Origin is { } origin)
            {
                cors.AddDefaultPolicy(policy => policy
                    .WithOrigins(origin)
                    .AllowCredentials()
                    .WithMethods(HttpMethods.Get, HttpMethods.Post)
                    .WithHeaders("Content-Type", CsrfProtectionMiddleware.HeaderName));
            }
        });

        return services;
    }

    public static IApplicationBuilder UseFrontendSecurity(this IApplicationBuilder app) =>
        app.UseCors().UseMiddleware<CsrfProtectionMiddleware>();
}

internal sealed class FrontendOptionsValidator : IValidateOptions<FrontendOptions>
{
    public ValidateOptionsResult Validate(string? name, FrontendOptions options) =>
        options.BindingErrors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(options.BindingErrors);
}
