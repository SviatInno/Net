using FEDept.BackendCourse.GroupA1.Api.Template.Security;
using Microsoft.Extensions.Options;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Authentication;

/// <summary>
/// The only place tokens leave the server: host-only, HttpOnly, Secure cookies.
/// <c>SameSite=Strict</c> by default, <c>None</c> when the trusted frontend is on another site.
/// </summary>
public sealed class AuthCookies(IOptions<FrontendOptions> frontend)
{
    public const string AccessCookie = "access_token";
    public const string RefreshCookie = "refresh_token";
    public const string AccessPath = "/";
    public const string RefreshPath = "/auth/refresh";

    private readonly SameSiteMode _sameSite = frontend.Value.CrossSite ? SameSiteMode.None : SameSiteMode.Strict;

    /// <summary>Writes both cookies; call only after both tokens are signed.</summary>
    public void Set(HttpResponse response, TokenPair tokens)
    {
        response.Cookies.Append(AccessCookie, tokens.AccessToken, Options(AccessPath, LoginOptions.AccessTokenLifetime));
        response.Cookies.Append(RefreshCookie, tokens.RefreshToken, Options(RefreshPath, LoginOptions.RefreshTokenLifetime));
    }

    /// <summary>Expires both cookies with the same Path / Secure / SameSite they were set with.</summary>
    public void Clear(HttpResponse response)
    {
        response.Cookies.Delete(AccessCookie, Options(AccessPath, maxAge: null));
        response.Cookies.Delete(RefreshCookie, Options(RefreshPath, maxAge: null));
    }

    // No Domain: the cookie stays host-only.
    private CookieOptions Options(string path, TimeSpan? maxAge) => new()
    {
        HttpOnly = true,
        Secure = true,
        SameSite = _sameSite,
        Path = path,
        MaxAge = maxAge,
        IsEssential = true,
    };
}
