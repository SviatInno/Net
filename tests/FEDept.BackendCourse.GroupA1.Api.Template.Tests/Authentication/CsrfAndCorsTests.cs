using System.Net;
using FEDept.BackendCourse.GroupA1.Api.Template.Tests.Infrastructure;
using Microsoft.Net.Http.Headers;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Authentication;

/// <summary>Origin / CSRF checks and the cross-origin cookie policy (section 1.3.3).</summary>
[Collection(PostgresCollection.Name)]
public sealed class CsrfAndCorsTests(PostgresFixture postgres)
{
    private const string Frontend = "https://app.example.com";

    [Fact]
    public async Task SameOriginDefault_RejectsForeignOrigin_AcceptsOwnOriginAndNonBrowserClients()
    {
        await using var api = ApiFactory.CreateForLogin(postgres, confirmation: false);
        var client = api.CreateCookielessClient();

        using var foreign = await client.SendAsync(Post("/auth/logout", origin: "https://evil.example"));
        using var foreignLogin = await client.SendAsync(Post("/auth/login", origin: "https://evil.example"));
        using var nullOrigin = await client.SendAsync(Post("/auth/logout", origin: "null"));
        using var own = await client.SendAsync(Post("/auth/logout", origin: "https://localhost"));
        using var noOrigin = await client.SendAsync(Post("/auth/logout"));

        foreach (var rejected in new[] { foreign, foreignLogin, nullOrigin })
        {
            Assert.Equal(HttpStatusCode.Forbidden, rejected.StatusCode);
            Assert.Equal("csrf_rejected", (await rejected.ProblemAsync()).Code);
            Assert.Empty(rejected.SetCookies());
        }

        Assert.Equal(HttpStatusCode.NoContent, own.StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, noOrigin.StatusCode);
        Assert.Contains(api.Logs.Entries, e => e.Contains("CSRF check rejected") && e.Contains("untrusted_origin"));
    }

    [Fact]
    public async Task TrustedOrigin_RequiresExactOriginAndHeader()
    {
        await using var api = ApiFactory.CreateForLogin(postgres, confirmation: false, settings: new Dictionary<string, string?>
        {
            ["FRONTEND_ORIGIN"] = Frontend + "/",
        });
        var client = api.CreateCookielessClient();
        var email = await client.CreateActiveUserAsync();

        using var ok = await client.SendAsync(Post("/auth/login", Frontend, csrfHeader: "1", email: email));
        using var noHeader = await client.SendAsync(Post("/auth/login", Frontend, email: email));
        using var wrongHeader = await client.SendAsync(Post("/auth/logout", Frontend, csrfHeader: "true"));
        using var otherPort = await client.SendAsync(Post("/auth/logout", Frontend + ":8443", csrfHeader: "1"));
        using var otherScheme = await client.SendAsync(Post("/auth/logout", "http://app.example.com", csrfHeader: "1"));

        Assert.Equal(HttpStatusCode.NoContent, ok.StatusCode);
        Assert.Equal(Frontend, ok.Headers.GetValues(HeaderNames.AccessControlAllowOrigin).Single());
        Assert.Equal("true", ok.Headers.GetValues(HeaderNames.AccessControlAllowCredentials).Single());
        // Same site (subdomain of the API's site): cookies stay SameSite=Strict.
        Assert.Equal(SameSiteMode.Strict, ok.AuthCookies().Access.SameSite);

        foreach (var rejected in new[] { noHeader, wrongHeader, otherPort, otherScheme })
        {
            Assert.Equal(HttpStatusCode.Forbidden, rejected.StatusCode);
            Assert.Equal("csrf_rejected", (await rejected.ProblemAsync()).Code);
        }
    }

    [Fact]
    public async Task TrustedOrigin_PreflightAllowsCredentialsAndCsrfHeader()
    {
        await using var api = ApiFactory.CreateForLogin(postgres, confirmation: false, settings: new Dictionary<string, string?>
        {
            ["FRONTEND_ORIGIN"] = Frontend,
        });
        var client = api.CreateCookielessClient();
        using var request = new HttpRequestMessage(HttpMethod.Options, "/auth/login");
        request.Headers.Add(HeaderNames.Origin, Frontend);
        request.Headers.Add(HeaderNames.AccessControlRequestMethod, "POST");
        request.Headers.Add(HeaderNames.AccessControlRequestHeaders, "content-type,x-csrf-protection");

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal(Frontend, response.Headers.GetValues(HeaderNames.AccessControlAllowOrigin).Single());
        Assert.Equal("true", response.Headers.GetValues(HeaderNames.AccessControlAllowCredentials).Single());
        Assert.Contains("x-csrf-protection", response.Headers.GetValues(HeaderNames.AccessControlAllowHeaders).Single().ToLowerInvariant());
    }

    [Fact]
    public async Task CrossSiteFrontend_GetsSameSiteNoneSecureCookies_OnLoginAndLogout()
    {
        await using var api = ApiFactory.CreateForLogin(postgres, confirmation: false, settings: new Dictionary<string, string?>
        {
            ["FRONTEND_ORIGIN"] = "https://frontend.example.org",
            ["FRONTEND_CROSS_SITE"] = "true",
        });
        var client = api.CreateCookielessClient();
        var email = await client.CreateActiveUserAsync();

        using var login = await client.SendAsync(Post("/auth/login", "https://frontend.example.org", csrfHeader: "1", email: email));
        using var logout = await client.SendAsync(Post("/auth/logout", "https://frontend.example.org", csrfHeader: "1"));

        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
        foreach (var cookie in login.SetCookies().Concat(logout.SetCookies()))
        {
            Assert.Equal(SameSiteMode.None, cookie.SameSite);
            Assert.True(cookie.Secure);
            Assert.True(cookie.HttpOnly);
        }
    }

    private static HttpRequestMessage Post(string path, string? origin = null, string? csrfHeader = null, string? email = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = System.Net.Http.Json.JsonContent.Create(new { email = email ?? "user@example.com", password = TestData.Password }),
        };
        if (origin is not null)
        {
            request.Headers.Add(HeaderNames.Origin, origin);
        }

        if (csrfHeader is not null)
        {
            request.Headers.Add("X-CSRF-Protection", csrfHeader);
        }

        return request;
    }
}
