using System.Net;
using FEDept.BackendCourse.GroupA1.Api.Template.Features.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Authentication;

/// <summary>A database outage is 503, never 401: clients must not drop a valid session because of it.</summary>
public sealed class DatabaseUnavailableTests : IAsyncLifetime
{
    // Nothing listens on port 1: every query fails at connect time.
    private readonly ApiFactory _api = new(
        "Host=127.0.0.1;Port=1;Database=none;Username=none;Password=none;Timeout=3",
        new Dictionary<string, string?> { ["LOGIN_EMAIL_CONFIRMATION_ENABLED"] = "false" });

    private HttpClient _client = null!;
    private TokenPair _tokens = null!;

    public Task InitializeAsync()
    {
        _client = _api.CreateCookielessClient();
        _tokens = _api.Services.GetRequiredService<TokenService>().IssuePair(Guid.NewGuid());
        return Task.CompletedTask;
    }

    public async Task DisposeAsync() => await _api.DisposeAsync();

    [Fact]
    public async Task Refresh_Returns503_WithoutCookies()
    {
        using var response = await _client.RefreshAsync(_tokens.RefreshToken);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("service_unavailable", (await response.ProblemAsync()).Code);
        Assert.Empty(response.SetCookies());
    }

    [Fact]
    public async Task AccessCheck_Returns503()
    {
        using var response = await _client.MeAsync(_tokens.AccessToken);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("service_unavailable", (await response.ProblemAsync()).Code);
    }

    [Fact]
    public async Task Login_Returns503()
    {
        using var response = await _client.LoginAsync("user@example.com");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("service_unavailable", (await response.ProblemAsync()).Code);
    }
}
