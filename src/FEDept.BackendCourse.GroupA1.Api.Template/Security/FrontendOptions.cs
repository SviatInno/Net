namespace FEDept.BackendCourse.GroupA1.Api.Template.Security;

/// <summary>
/// Where the trusted frontend lives. Default (no origin): the frontend and the API share one origin,
/// so there is no CORS policy and every cross-origin unsafe request is rejected.
/// </summary>
public sealed class FrontendOptions
{
    public const string OriginKey = "FRONTEND_ORIGIN";
    public const string CrossSiteKey = "FRONTEND_CROSS_SITE";

    /// <summary>Exact trusted origin (<c>scheme://host[:port]</c>), or <c>null</c> for same-origin deployments.</summary>
    public string? Origin { get; set; }

    /// <summary>
    /// The trusted origin is on another site (different registrable domain or scheme):
    /// auth cookies then need <c>SameSite=None</c> to be sent at all.
    /// </summary>
    public bool CrossSite { get; set; }

    /// <summary>Set by binding when a value could not be parsed; reported by validation.</summary>
    internal List<string> BindingErrors { get; } = [];

    internal static void Bind(FrontendOptions options, IConfiguration configuration)
    {
        var origin = configuration[OriginKey];
        if (!string.IsNullOrWhiteSpace(origin))
        {
            if (Uri.TryCreate(origin.Trim(), UriKind.Absolute, out var uri)
                && uri.Scheme is "https" or "http"
                && uri.AbsolutePath == "/" && uri.Query.Length == 0 && uri.Fragment.Length == 0
                && uri.UserInfo.Length == 0)
            {
                // Same form as a browser's Origin header: lower-case, no default port, no trailing slash.
                options.Origin = uri.GetLeftPart(UriPartial.Authority);
            }
            else
            {
                options.BindingErrors.Add($"{OriginKey} must be an origin such as https://app.example.com (no path).");
            }
        }

        var crossSite = configuration[CrossSiteKey];
        if (!string.IsNullOrWhiteSpace(crossSite))
        {
            if (bool.TryParse(crossSite, out var value))
            {
                options.CrossSite = value;
            }
            else
            {
                options.BindingErrors.Add($"{CrossSiteKey} must be true or false.");
            }
        }

        if (options.CrossSite && options.Origin is null)
        {
            options.BindingErrors.Add($"{CrossSiteKey}=true requires {OriginKey}.");
        }
    }
}
