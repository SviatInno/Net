using Microsoft.Extensions.Options;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Authentication;

/// <summary>
/// Login email confirmation settings. Read per request (<see cref="IOptionsSnapshot{TOptions}"/>):
/// a configuration change applies to new logins only; an existing attempt keeps its own method.
/// </summary>
public sealed class LoginOptions
{
    public const string ConfirmationEnabledKey = "LOGIN_EMAIL_CONFIRMATION_ENABLED";
    public const string ConfirmationMethodKey = "LOGIN_EMAIL_CONFIRMATION_METHOD";
    public const string MagicLinkUrlKey = "LOGIN_MAGIC_LINK_URL";

    // Contract values (sections 1.3 and 1.6); part of the API, so not configurable.
    public static readonly TimeSpan AccessTokenLifetime = TimeSpan.FromMinutes(15);
    public static readonly TimeSpan RefreshTokenLifetime = TimeSpan.FromDays(30);
    public static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan ChallengeTtl = TimeSpan.FromMinutes(10);
    public static readonly TimeSpan ResendCooldown = TimeSpan.FromSeconds(60);
    public const int MaxCodeAttempts = 5;

    public const int LoginRequestsPerIpPerMinute = 30;
    public const int RefreshRequestsPerIpPerMinute = 30;
    public const int MaxFailuresPerEmailAndIp = 5;
    public static readonly TimeSpan FailureWindow = TimeSpan.FromMinutes(15);

    public bool ConfirmationEnabled { get; set; }

    public LoginChallengeMethod ConfirmationMethod { get; set; } = LoginChallengeMethod.Otp;

    /// <summary>Frontend page that reads <c>#token=...</c> and POSTs it to /auth/login/confirm.</summary>
    public string MagicLinkUrl { get; set; } = string.Empty;

    internal List<string> BindingErrors { get; } = [];

    internal static void Bind(LoginOptions options, IConfiguration configuration)
    {
        var enabled = configuration[ConfirmationEnabledKey];
        if (!string.IsNullOrWhiteSpace(enabled))
        {
            if (bool.TryParse(enabled, out var value))
            {
                options.ConfirmationEnabled = value;
            }
            else
            {
                options.BindingErrors.Add($"{ConfirmationEnabledKey} must be true or false.");
            }
        }

        var method = configuration[ConfirmationMethodKey];
        if (!string.IsNullOrWhiteSpace(method))
        {
            if (LoginChallengeMethods.TryParse(method.Trim(), out var value))
            {
                options.ConfirmationMethod = value;
            }
            else
            {
                options.BindingErrors.Add($"{ConfirmationMethodKey} must be otp or magic_link.");
            }
        }

        // Always required: an already issued magic link attempt can be resent after the method is switched to otp.
        options.MagicLinkUrl = configuration[MagicLinkUrlKey]?.Trim() ?? string.Empty;
        if (!Uri.TryCreate(options.MagicLinkUrl, UriKind.Absolute, out var url)
            || url.Scheme is not ("https" or "http")
            || url.Fragment.Length > 0)
        {
            options.BindingErrors.Add($"{MagicLinkUrlKey} must be an absolute http(s) URL without a fragment.");
        }
    }
}

internal sealed class LoginOptionsValidator : IValidateOptions<LoginOptions>
{
    public ValidateOptionsResult Validate(string? name, LoginOptions options) =>
        options.BindingErrors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(options.BindingErrors);
}
