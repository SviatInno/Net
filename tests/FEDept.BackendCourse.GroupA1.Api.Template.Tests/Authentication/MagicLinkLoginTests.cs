using System.Net;
using System.Net.Http.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Features.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Authentication;

/// <summary>Login with an emailed magic link (token in the URL fragment, confirmed by POST).</summary>
[Collection(PostgresCollection.Name)]
public sealed class MagicLinkLoginTests(PostgresFixture postgres) : IAsyncLifetime
{
    private readonly ApiFactory _api = ApiFactory.CreateForLogin(postgres, confirmation: true, method: "magic_link");
    private HttpClient _client = null!;

    public Task InitializeAsync()
    {
        _client = _api.CreateCookielessClient();
        return Task.CompletedTask;
    }

    public async Task DisposeAsync() => await _api.DisposeAsync();

    [Fact]
    public async Task Login_SendsLinkWithTokenInFragment_AndConfirmSetsCookies()
    {
        var email = await _client.CreateActiveUserAsync();

        using var login = await _client.LoginAsync(email);

        Assert.Equal(HttpStatusCode.Accepted, login.StatusCode);
        var body = await login.Content.ReadFromJsonAsync<LoginPendingBody>();
        Assert.Equal(new LoginPendingBody(true, "magic_link", body!.AttemptId, 600, 60), body);
        Assert.Contains("http://localhost:5173/login/confirm#token=", _api.Emails.LastTo(email).TextBody);
        var token = _api.Emails.LastLoginTokenFor(email);
        Assert.StartsWith($"{body.AttemptId}.", token);
        Assert.Equal(43, token[(token.IndexOf('.') + 1)..].Length); // 32 bytes, base64url
        Assert.DoesNotContain(token, await login.Content.ReadAsStringAsync());

        using var confirm = await _client.ConfirmLoginTokenAsync(token);

        Assert.Equal(HttpStatusCode.NoContent, confirm.StatusCode);
        using var me = await _client.MeAsync(confirm.AuthCookies().AccessToken);
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);

        using var reuse = await _client.ConfirmLoginTokenAsync(token);
        Assert.Equal(HttpStatusCode.BadRequest, reuse.StatusCode);
    }

    [Fact]
    public async Task Confirm_WrongSecret_Returns400_WithoutCounter()
    {
        var email = await _client.CreateActiveUserAsync();
        using var login = await _client.LoginAsync(email);
        var attemptId = (await login.Content.ReadFromJsonAsync<LoginPendingBody>())!.AttemptId;
        var token = _api.Emails.LastLoginTokenFor(email);
        var wrong = $"{attemptId}.{new string('A', 43)}";

        for (var i = 0; i < 6; i++)
        {
            using var response = await _client.ConfirmLoginTokenAsync(wrong);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("invalid_confirmation", (await response.ProblemAsync()).Code);
        }

        Assert.Equal(0, await _api.WithDbAsync(db => db.LoginChallenges.Where(c => c.Id == attemptId).Select(c => c.Attempts).SingleAsync()));
        using var confirm = await _client.ConfirmLoginTokenAsync(token);
        Assert.Equal(HttpStatusCode.NoContent, confirm.StatusCode);
    }

    [Theory]
    [InlineData("garbage")]
    [InlineData("00000000-0000-0000-0000-000000000000.short")]
    public async Task Confirm_MalformedToken_Returns400(string token)
    {
        using var response = await _client.ConfirmLoginTokenAsync(token);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_confirmation", (await response.ProblemAsync()).Code);
    }

    [Fact]
    public async Task Confirm_OtpCodeForMagicLinkAttempt_Returns400()
    {
        var email = await _client.CreateActiveUserAsync();
        using var login = await _client.LoginAsync(email);
        var attemptId = (await login.Content.ReadFromJsonAsync<LoginPendingBody>())!.AttemptId;

        using var response = await _client.ConfirmLoginCodeAsync(attemptId, "123456");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_confirmation", (await response.ProblemAsync()).Code);
    }

    [Fact]
    public async Task Resend_ReplacesLink_OldLinkStopsWorking()
    {
        var email = await _client.CreateActiveUserAsync();
        using var login = await _client.LoginAsync(email);
        var attemptId = (await login.Content.ReadFromJsonAsync<LoginPendingBody>())!.AttemptId;
        var oldToken = _api.Emails.LastLoginTokenFor(email);
        _api.Time.Advance(TimeSpan.FromSeconds(60));

        using var resend = await _client.ResendLoginAsync(attemptId);

        Assert.Equal(HttpStatusCode.Accepted, resend.StatusCode);
        Assert.Equal(new ResendBody("magic_link", attemptId, 600, 60), await resend.Content.ReadFromJsonAsync<ResendBody>());
        var newToken = _api.Emails.LastLoginTokenFor(email);
        Assert.NotEqual(oldToken, newToken);
        using var old = await _client.ConfirmLoginTokenAsync(oldToken);
        Assert.Equal(HttpStatusCode.BadRequest, old.StatusCode);
        using var confirm = await _client.ConfirmLoginTokenAsync(newToken);
        Assert.Equal(HttpStatusCode.NoContent, confirm.StatusCode);
    }

    [Fact]
    public async Task ExistingAttempt_KeepsItsMethod_AfterConfigurationSwitchesToOtpOrOff()
    {
        var email = await _client.CreateActiveUserAsync();
        using var login = await _client.LoginAsync(email);
        var attemptId = (await login.Content.ReadFromJsonAsync<LoginPendingBody>())!.AttemptId;

        await using var otpApi = ApiFactory.CreateForLogin(postgres, confirmation: true, method: "otp");
        var otpClient = otpApi.CreateCookielessClient();
        otpApi.Time.Advance(TimeSpan.FromSeconds(60));
        using var resend = await otpClient.ResendLoginAsync(attemptId);
        Assert.Equal(HttpStatusCode.Accepted, resend.StatusCode);
        Assert.Equal("magic_link", (await resend.Content.ReadFromJsonAsync<ResendBody>())!.Method);
        var token = otpApi.Emails.LastLoginTokenFor(email);

        await using var offApi = ApiFactory.CreateForLogin(postgres, confirmation: false);
        using var confirm = await offApi.CreateCookielessClient().ConfirmLoginTokenAsync(token);
        Assert.Equal(HttpStatusCode.NoContent, confirm.StatusCode);
        Assert.Equal(
            LoginChallengeConsumedReason.Confirmed,
            await offApi.WithDbAsync(db => db.LoginChallenges.Where(c => c.Id == attemptId).Select(c => c.ConsumedReason).SingleAsync()));
    }
}
