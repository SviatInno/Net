using System.Net;
using System.Net.Http.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Tests.Infrastructure;
using Microsoft.Net.Http.Headers;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Authentication;

public sealed record LoginPendingBody(bool ConfirmationRequired, string Method, Guid AttemptId, int ExpiresInSeconds, int ResendAfterSeconds);

public sealed record ResendBody(string Method, Guid AttemptId, int ExpiresInSeconds, int ResendAfterSeconds);

public sealed record AuthProblemBody(
    int Status,
    string? Code,
    string? Title,
    string? Detail,
    Dictionary<string, string[]>? Errors,
    bool? ConfirmationRequired,
    string? Method,
    Guid? AttemptId,
    int? RetryAfterSeconds);

public sealed record MeBody(Guid UserId);

/// <summary>The two cookies a successful login, confirm or refresh sets.</summary>
public sealed record AuthCookiePair(SetCookieHeaderValue Access, SetCookieHeaderValue Refresh)
{
    public string AccessToken => Access.Value.ToString();

    public string RefreshToken => Refresh.Value.ToString();
}

public static class AuthTestData
{
    /// <summary>Registers an active user (the login factory turns registration confirmation off).</summary>
    public static async Task<string> CreateActiveUserAsync(this HttpClient client, string password = TestData.Password)
    {
        var email = TestData.NewEmail();
        using var response = await client.RegisterAsync(email, password);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return email;
    }

    public static Task<HttpResponseMessage> LoginAsync(this HttpClient client, string? email, string? password = TestData.Password) =>
        client.PostAsJsonAsync("/auth/login", new { email, password });

    public static Task<HttpResponseMessage> ConfirmLoginCodeAsync(this HttpClient client, Guid attemptId, string code) =>
        client.PostAsJsonAsync("/auth/login/confirm", new { attemptId = attemptId.ToString(), code });

    public static Task<HttpResponseMessage> ConfirmLoginTokenAsync(this HttpClient client, string token) =>
        client.PostAsJsonAsync("/auth/login/confirm", new { token });

    public static Task<HttpResponseMessage> ResendLoginAsync(this HttpClient client, Guid attemptId) =>
        client.PostAsJsonAsync("/auth/login/resend", new { attemptId = attemptId.ToString() });

    public static Task<HttpResponseMessage> RefreshAsync(this HttpClient client, string? refreshToken) =>
        client.SendAsync(WithCookie(HttpMethod.Post, "/auth/refresh", "refresh_token", refreshToken));

    public static Task<HttpResponseMessage> MeAsync(this HttpClient client, string? accessToken) =>
        client.SendAsync(WithCookie(HttpMethod.Get, "/auth/me", "access_token", accessToken));

    public static Task<HttpResponseMessage> LogoutAsync(this HttpClient client) =>
        client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/auth/logout"));

    /// <summary>Logs in with confirmation off and returns the cookie pair.</summary>
    public static async Task<AuthCookiePair> LoginDirectAsync(this HttpClient client, string email, string password = TestData.Password)
    {
        using var response = await client.LoginAsync(email, password);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        return response.AuthCookies();
    }

    public static IReadOnlyList<SetCookieHeaderValue> SetCookies(this HttpResponseMessage response) =>
        response.Headers.TryGetValues(HeaderNames.SetCookie, out var values)
            ? SetCookieHeaderValue.ParseList(values.ToList()).ToList()
            : [];

    public static AuthCookiePair AuthCookies(this HttpResponseMessage response)
    {
        var cookies = response.SetCookies();
        return new AuthCookiePair(
            Assert.Single(cookies, c => c.Name == "access_token"),
            Assert.Single(cookies, c => c.Name == "refresh_token"));
    }

    public static async Task<AuthProblemBody> ProblemAsync(this HttpResponseMessage response) =>
        (await response.Content.ReadFromJsonAsync<AuthProblemBody>())!;

    private static HttpRequestMessage WithCookie(HttpMethod method, string path, string name, string? value)
    {
        var request = new HttpRequestMessage(method, path);
        if (value is not null)
        {
            request.Headers.Add(HeaderNames.Cookie, $"{name}={value}");
        }

        return request;
    }
}
