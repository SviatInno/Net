using System.Net;
using System.Net.Http.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Tests.Infrastructure;
using FEDept.BackendCourse.GroupA1.Api.Template.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.Net.Http.Headers;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Authentication;

/// <summary>Login without email confirmation: section 1.3.1 (direct path), 1.3.3, 1.4.</summary>
[Collection(PostgresCollection.Name)]
public sealed class DirectLoginTests(PostgresFixture postgres) : IAsyncLifetime
{
    private readonly ApiFactory _api = ApiFactory.CreateForLogin(postgres, confirmation: false);
    private HttpClient _client = null!;

    public Task InitializeAsync()
    {
        _client = _api.CreateCookielessClient();
        return Task.CompletedTask;
    }

    public async Task DisposeAsync() => await _api.DisposeAsync();

    [Fact]
    public async Task Login_ValidCredentials_Returns204_WithBothCookies_AndNoBody()
    {
        var email = await _client.CreateActiveUserAsync();

        using var response = await _client.LoginAsync(email);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsByteArrayAsync());
        var (access, refresh) = response.AuthCookies();

        Assert.True(access.HttpOnly);
        Assert.True(access.Secure);
        Assert.Equal(SameSiteMode.Strict, access.SameSite);
        Assert.Equal("/", access.Path.ToString());
        Assert.Equal(TimeSpan.FromSeconds(900), access.MaxAge);
        Assert.True(access.Domain.HasValue is false);

        Assert.True(refresh.HttpOnly);
        Assert.True(refresh.Secure);
        Assert.Equal(SameSiteMode.Strict, refresh.SameSite);
        Assert.Equal("/auth/refresh", refresh.Path.ToString());
        Assert.Equal(TimeSpan.FromSeconds(2_592_000), refresh.MaxAge);
        Assert.True(refresh.Domain.HasValue is false);
    }

    [Fact]
    public async Task Login_TokensHaveExactlyTheContractClaims_SignedWithSeparateKeys()
    {
        var email = await _client.CreateActiveUserAsync();
        var userId = await _api.WithDbAsync(db => db.Users.Where(u => u.Email == email).Select(u => u.Id).SingleAsync());

        var cookies = await _client.LoginDirectAsync(email);

        var access = new JsonWebToken(cookies.AccessToken);
        var refresh = new JsonWebToken(cookies.RefreshToken);
        foreach (var (token, use, lifetime) in new[] { (access, "access", 900L), (refresh, "refresh", 2_592_000L) })
        {
            Assert.Equal("HS256", token.Alg);
            Assert.Equal(
                ["aud", "exp", "iat", "iss", "sub", "token_use"],
                token.Claims.Select(c => c.Type).Distinct().Order());
            Assert.Equal(userId.ToString(), token.Subject);
            Assert.Equal(ApiFactory.JwtIssuer, token.Issuer);
            Assert.Equal([ApiFactory.JwtAudience], token.Audiences);
            Assert.Equal(use, token.GetPayloadValue<string>("token_use"));
            Assert.Equal(lifetime, token.GetPayloadValue<long>("exp") - token.GetPayloadValue<long>("iat"));
        }

        // A refresh token is not an access token and vice versa (different key and token_use).
        using var refreshAsAccess = await _client.MeAsync(cookies.RefreshToken);
        using var accessAsRefresh = await _client.RefreshAsync(cookies.AccessToken);
        Assert.Equal(HttpStatusCode.Unauthorized, refreshAsAccess.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, accessAsRefresh.StatusCode);
    }

    [Fact]
    public async Task Login_NormalizesEmail_ButNotPassword()
    {
        var email = await _client.CreateActiveUserAsync();

        using var normalized = await _client.LoginAsync($"  {email.ToUpperInvariant()} ");
        using var paddedPassword = await _client.LoginAsync(email, $" {TestData.Password}");

        Assert.Equal(HttpStatusCode.NoContent, normalized.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, paddedPassword.StatusCode);
    }

    [Theory]
    [InlineData(UserStatus.Pending)]
    [InlineData(UserStatus.Blocked)]
    [InlineData(UserStatus.Deleting)]
    [InlineData(UserStatus.Deleted)]
    public async Task Login_UnknownEmail_WrongPassword_AndInactiveStatus_GiveOneNeutral401(UserStatus status)
    {
        var inactive = await _client.CreateActiveUserAsync();
        await SetStatusAsync(inactive, status);
        var active = await _client.CreateActiveUserAsync();

        using var unknown = await _client.LoginAsync(TestData.NewEmail());
        using var wrongPassword = await _client.LoginAsync(active, "Wrong-passw0rd");
        using var notActive = await _client.LoginAsync(inactive);

        var bodies = new List<string>();
        foreach (var response in new[] { unknown, wrongPassword, notActive })
        {
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Empty(response.SetCookies());
            Assert.Equal("invalid_credentials", (await response.ProblemAsync()).Code);
            bodies.Add(Normalize(await response.Content.ReadAsStringAsync()));
        }

        // Identical code, text and shape: nothing tells the cases apart.
        Assert.Single(bodies.Distinct());
    }

    [Theory]
    [InlineData(null, TestData.Password, "email")]
    [InlineData("not-an-email", TestData.Password, "email")]
    [InlineData("user@example.com", null, "password")]
    [InlineData("user@example.com", "", "password")]
    public async Task Login_MalformedBody_Returns400(string? email, string? password, string field)
    {
        using var response = await _client.LoginAsync(email, password);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var problem = await response.ProblemAsync();
        Assert.Equal("validation_failed", problem.Code);
        Assert.True(problem.Errors!.ContainsKey(field));
    }

    [Fact]
    public async Task Login_SixthCheckAfterFiveFailures_IsRateLimited_EvenWithCorrectPassword()
    {
        var email = await _client.CreateActiveUserAsync();
        for (var i = 0; i < 5; i++)
        {
            using var wrong = await _client.LoginAsync(email, "Wrong-passw0rd");
            Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        }

        using var blocked = await _client.LoginAsync(email);

        Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);
        Assert.Equal("rate_limited", (await blocked.ProblemAsync()).Code);
        Assert.NotNull(blocked.Headers.RetryAfter);

        // Another email from the same IP is not affected; the pair recovers after 15 minutes.
        using var other = await _client.LoginAsync(await _client.CreateActiveUserAsync());
        Assert.Equal(HttpStatusCode.NoContent, other.StatusCode);
        _api.Time.Advance(TimeSpan.FromMinutes(15));
        using var later = await _client.LoginAsync(email);
        Assert.Equal(HttpStatusCode.NoContent, later.StatusCode);
    }

    [Fact]
    public async Task Login_MoreThan30RequestsPerMinuteFromOneIp_Returns429()
    {
        for (var i = 0; i < 30; i++)
        {
            using var response = await _client.LoginAsync("not-an-email");
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }

        using var limited = await _client.LoginAsync("not-an-email");

        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.Equal("rate_limited", (await limited.ProblemAsync()).Code);
    }

    [Fact]
    public async Task Me_WithValidAccessCookie_ReturnsUserId_Only()
    {
        var email = await _client.CreateActiveUserAsync();
        var cookies = await _client.LoginDirectAsync(email);
        var userId = await _api.WithDbAsync(db => db.Users.Where(u => u.Email == email).Select(u => u.Id).SingleAsync());

        using var response = await _client.MeAsync(cookies.AccessToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(new MeBody(userId), await response.Content.ReadFromJsonAsync<MeBody>());
    }

    [Fact]
    public async Task Me_AccessExpiresAfter15Minutes_WithAtMost30SecondsSkew()
    {
        var cookies = await _client.LoginDirectAsync(await _client.CreateActiveUserAsync());

        _api.Time.Advance(TimeSpan.FromMinutes(15) + TimeSpan.FromSeconds(29));
        using var withinSkew = await _client.MeAsync(cookies.AccessToken);
        _api.Time.Advance(TimeSpan.FromSeconds(2));
        using var expired = await _client.MeAsync(cookies.AccessToken);

        Assert.Equal(HttpStatusCode.OK, withinSkew.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, expired.StatusCode);
        Assert.Equal("invalid_session", (await expired.ProblemAsync()).Code);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("not-a-jwt")]
    [InlineData("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.")]
    public async Task Me_WithoutValidAccessCookie_Returns401InvalidSession(string? token)
    {
        using var response = await _client.MeAsync(token);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("invalid_session", (await response.ProblemAsync()).Code);
    }

    [Fact]
    public async Task Me_TamperedSignature_Returns401()
    {
        var cookies = await _client.LoginDirectAsync(await _client.CreateActiveUserAsync());
        var parts = cookies.AccessToken.Split('.');
        var tampered = $"{parts[0]}.{parts[1]}.{(parts[2][0] == 'A' ? 'B' : 'A')}{parts[2][1..]}";

        using var response = await _client.MeAsync(tampered);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(_api.Logs.Entries, e => e.Contains("Access rejected") && e.Contains("signature"));
    }

    [Theory]
    [InlineData(UserStatus.Blocked)]
    [InlineData(UserStatus.Deleted)]
    public async Task Me_AfterUserStopsBeingActive_Returns401(UserStatus status)
    {
        var email = await _client.CreateActiveUserAsync();
        var cookies = await _client.LoginDirectAsync(email);
        await SetStatusAsync(email, status);

        using var response = await _client.MeAsync(cookies.AccessToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("invalid_session", (await response.ProblemAsync()).Code);
    }

    [Fact]
    public async Task Me_AfterUserIsRemoved_Returns401()
    {
        var email = await _client.CreateActiveUserAsync();
        var cookies = await _client.LoginDirectAsync(email);
        await _api.WithDbAsync(db => db.Users.Where(u => u.Email == email).ExecuteDeleteAsync());

        using var response = await _client.MeAsync(cookies.AccessToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Refresh_IssuesNewPair_WithoutPassword_AndOldRefreshStaysValid()
    {
        var cookies = await _client.LoginDirectAsync(await _client.CreateActiveUserAsync());
        _api.Time.Advance(TimeSpan.FromMinutes(20));
        using var expiredAccess = await _client.MeAsync(cookies.AccessToken);
        Assert.Equal(HttpStatusCode.Unauthorized, expiredAccess.StatusCode);

        using var response = await _client.RefreshAsync(cookies.RefreshToken);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsByteArrayAsync());
        var renewed = response.AuthCookies();
        Assert.Equal(TimeSpan.FromSeconds(900), renewed.Access.MaxAge);
        Assert.Equal("/auth/refresh", renewed.Refresh.Path.ToString());
        using var me = await _client.MeAsync(renewed.AccessToken);
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);

        // No server-side sessions: rotation does not revoke the used refresh token.
        using var reused = await _client.RefreshAsync(cookies.RefreshToken);
        Assert.Equal(HttpStatusCode.NoContent, reused.StatusCode);
    }

    [Fact]
    public async Task Refresh_ExpiresAfter30Days()
    {
        var cookies = await _client.LoginDirectAsync(await _client.CreateActiveUserAsync());

        _api.Time.Advance(TimeSpan.FromDays(30) + TimeSpan.FromSeconds(31));
        using var response = await _client.RefreshAsync(cookies.RefreshToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("invalid_session", (await response.ProblemAsync()).Code);
        Assert.Empty(response.SetCookies());
    }

    [Theory]
    [InlineData(UserStatus.Pending)]
    [InlineData(UserStatus.Blocked)]
    [InlineData(UserStatus.Deleting)]
    [InlineData(UserStatus.Deleted)]
    public async Task Refresh_ForNonActiveUser_Returns401_WithoutCookies(UserStatus status)
    {
        var email = await _client.CreateActiveUserAsync();
        var cookies = await _client.LoginDirectAsync(email);
        await SetStatusAsync(email, status);

        using var response = await _client.RefreshAsync(cookies.RefreshToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("invalid_session", (await response.ProblemAsync()).Code);
        Assert.Empty(response.SetCookies());
    }

    [Fact]
    public async Task Refresh_TakesTokenFromCookieOnly()
    {
        var cookies = await _client.LoginDirectAsync(await _client.CreateActiveUserAsync());

        using var request = new HttpRequestMessage(HttpMethod.Post, $"/auth/refresh?refresh_token={cookies.RefreshToken}")
        {
            Content = JsonContent.Create(new { refresh_token = cookies.RefreshToken, refreshToken = cookies.RefreshToken }),
        };
        request.Headers.Authorization = new("Bearer", cookies.RefreshToken);
        using var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("invalid_session", (await response.ProblemAsync()).Code);
    }

    [Fact]
    public async Task Logout_AlwaysReturns204_AndExpiresBothCookiesWithTheirAttributes()
    {
        using var response = await _client.LogoutAsync();

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsByteArrayAsync());
        var (access, refresh) = response.AuthCookies();
        foreach (var (cookie, path) in new[] { (access, "/"), (refresh, "/auth/refresh") })
        {
            Assert.Equal(string.Empty, cookie.Value.ToString());
            Assert.True(cookie.Expires < DateTimeOffset.UtcNow);
            Assert.Equal(path, cookie.Path.ToString());
            Assert.True(cookie.Secure);
            Assert.True(cookie.HttpOnly);
            Assert.Equal(SameSiteMode.Strict, cookie.SameSite);
            Assert.False(cookie.Domain.HasValue);
        }

        // Also with an invalid cookie present.
        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/logout");
        request.Headers.Add(HeaderNames.Cookie, "access_token=garbage; refresh_token=garbage");
        using var withGarbage = await _client.SendAsync(request);
        Assert.Equal(HttpStatusCode.NoContent, withGarbage.StatusCode);
    }

    [Fact]
    public async Task Logs_ContainAuditEvents_ButNoSecrets()
    {
        var email = await _client.CreateActiveUserAsync();
        using var wrong = await _client.LoginAsync(email, "Wrong-passw0rd");
        using var unknown = await _client.LoginAsync(TestData.NewEmail());
        var cookies = await _client.LoginDirectAsync(email);
        using var refresh = await _client.RefreshAsync(cookies.RefreshToken);
        using var logout = await _client.LogoutAsync();
        using var me = await _client.MeAsync(null);

        var logs = _api.Logs.Entries;
        Assert.Contains(logs, e => e.Contains("Login failed") && e.Contains("wrong_password"));
        Assert.Contains(logs, e => e.Contains("Login failed") && e.Contains("unknown_email") && e.Contains("email:"));
        Assert.Contains(logs, e => e.Contains("Login succeeded"));
        Assert.Contains(logs, e => e.Contains("Refresh succeeded"));
        Assert.Contains(logs, e => e.Contains("Logout"));
        Assert.Contains(logs, e => e.Contains("Access rejected") && e.Contains("missing"));
        Assert.DoesNotContain(logs, e =>
            e.Contains(email) || e.Contains(TestData.Password) || e.Contains("Wrong-passw0rd")
            || e.Contains(cookies.AccessToken) || e.Contains(cookies.RefreshToken)
            || e.Contains("$argon2"));
    }

    private Task<int> SetStatusAsync(string email, UserStatus status) =>
        _api.WithDbAsync(db => db.Users.Where(u => u.Email == email)
            .ExecuteUpdateAsync(u => u.SetProperty(x => x.Status, status)));

    // traceId differs per request; everything else must be identical.
    private static string Normalize(string json) =>
        System.Text.RegularExpressions.Regex.Replace(json, "\"traceId\":\"[^\"]*\"", string.Empty);
}
