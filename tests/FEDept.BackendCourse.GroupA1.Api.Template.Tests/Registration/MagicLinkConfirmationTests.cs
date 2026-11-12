using System.Net;
using System.Net.Http.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Tests.Infrastructure;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Registration;

[Collection(PostgresCollection.Name)]
public sealed class MagicLinkConfirmationTests(PostgresFixture postgres) : IAsyncLifetime
{
    private readonly ApiFactory _api = ApiFactory.Create(postgres, confirmation: true, method: "MagicLink");
    private HttpClient _client = null!;

    public Task InitializeAsync()
    {
        _client = _api.CreateApiClient();
        return Task.CompletedTask;
    }

    public async Task DisposeAsync() => await _api.DisposeAsync();

    [Fact]
    public async Task Register_SendsLink_TokenActivatesOnce()
    {
        var email = TestData.NewEmail();

        using var register = await _client.RegisterAsync(email);

        Assert.Equal(HttpStatusCode.Accepted, register.StatusCode);
        var body = await register.Content.ReadFromJsonAsync<PendingBody>();
        Assert.Equal("magic_link", body!.Method);
        var message = _api.Emails.LastTo(email);
        Assert.Contains("http://localhost:5173/register/confirm?token=", message.TextBody);
        var token = _api.Emails.LastTokenFor(email);
        Assert.Equal(32, Convert.FromBase64String(token.Replace('-', '+').Replace('_', '/') + "=").Length);
        Assert.DoesNotContain(token, await register.Content.ReadAsStringAsync());

        using var confirm = await _client.ConfirmTokenAsync(token);
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);
        Assert.Equal("active", (await confirm.Content.ReadFromJsonAsync<UserBody>())!.Status);

        using var reuse = await _client.ConfirmTokenAsync(token);
        Assert.Equal(HttpStatusCode.BadRequest, reuse.StatusCode);
    }

    [Fact]
    public async Task Confirm_ViaGet_IsNotAnEndpoint()
    {
        var email = TestData.NewEmail();
        (await _client.RegisterAsync(email)).Dispose();
        var token = _api.Emails.LastTokenFor(email);

        using var get = await _client.GetAsync($"/auth/register/confirm?token={token}");
        using var confirm = await _client.ConfirmTokenAsync(token);

        Assert.Equal(HttpStatusCode.MethodNotAllowed, get.StatusCode);
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);
    }

    [Fact]
    public async Task Resend_ReplacesLink_OldTokenStopsWorking()
    {
        var email = TestData.NewEmail();
        (await _client.RegisterAsync(email)).Dispose();
        var oldToken = _api.Emails.LastTokenFor(email);
        _api.Time.Advance(TimeSpan.FromSeconds(60));

        using var resend = await _client.ResendAsync(email);
        var newToken = _api.Emails.LastTokenFor(email);

        Assert.Equal(HttpStatusCode.Accepted, resend.StatusCode);
        Assert.Equal("magic_link", (await resend.Content.ReadFromJsonAsync<PendingBody>())!.Method);
        Assert.NotEqual(oldToken, newToken);
        using var old = await _client.ConfirmTokenAsync(oldToken);
        Assert.Equal(HttpStatusCode.BadRequest, old.StatusCode);
        using var confirm = await _client.ConfirmTokenAsync(newToken);
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);
    }

    [Fact]
    public async Task Confirm_ExpiredToken_Returns400()
    {
        var email = TestData.NewEmail();
        (await _client.RegisterAsync(email)).Dispose();
        _api.Time.Advance(TimeSpan.FromMinutes(10));

        using var response = await _client.ConfirmTokenAsync(_api.Emails.LastTokenFor(email));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Theory]
    [InlineData("not-a-token")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public async Task Confirm_UnknownOrMalformedToken_Returns400(string token)
    {
        using var response = await _client.ConfirmTokenAsync(token);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_confirmation", (await response.Content.ReadFromJsonAsync<ProblemBody>())!.Code);
    }

    [Fact]
    public async Task Confirm_WithBothTokenAndCode_Returns400()
    {
        using var response = await _client.PostAsJsonAsync("/auth/register/confirm",
            new { attemptId = Guid.NewGuid(), code = "123456", token = "x" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("validation_failed", (await response.Content.ReadFromJsonAsync<ProblemBody>())!.Code);
    }
}
