using System.Net.Http.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Data;
using FEDept.BackendCourse.GroupA1.Api.Template.Email;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Infrastructure;

/// <summary>The API against the shared test database, with a fake clock, email and log sink.</summary>
public sealed class ApiFactory(string connectionString, IDictionary<string, string?> settings)
    : WebApplicationFactory<Program>
{
    public const string HmacKey = "dGVzdC1rZXktdGVzdC1rZXktdGVzdC1rZXktdGVzdC1rZXk=";

    public FakeTimeProvider Time { get; } = new(DateTimeOffset.UtcNow);

    public FakeEmailSender Emails { get; } = new();

    public CapturingLoggerProvider Logs { get; } = new();

    public static ApiFactory Create(PostgresFixture postgres, bool confirmation, string method = "Otp", int registerPermits = 1000) =>
        new(postgres.ConnectionString, new Dictionary<string, string?>
        {
            ["Registration:ConfirmationEnabled"] = confirmation.ToString(),
            ["Registration:ConfirmationMethod"] = method,
            ["Registration:RegisterRateLimit:PermitLimit"] = registerPermits.ToString(),
        });

    public HttpClient CreateApiClient() =>
        CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost") });

    public async Task<T> WithDbAsync<T>(Func<AppDbContext, Task<T>> query)
    {
        await using var scope = Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        return await query(db);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("ConnectionStrings:Default", connectionString);
        builder.UseSetting("Registration:HmacKey", HmacKey);
        builder.UseSetting("Registration:MagicLinkUrl", "http://localhost:5173/register/confirm");
        builder.UseSetting("Registration:ResendRateLimit:PermitLimit", "1000");
        foreach (var (key, value) in settings)
        {
            builder.UseSetting(key, value);
        }

        builder.ConfigureLogging(logging => logging.ClearProviders().AddProvider(Logs).SetMinimumLevel(LogLevel.Trace));
        builder.ConfigureTestServices(services =>
        {
            services.AddSingleton<TimeProvider>(Time);
            services.AddSingleton<IEmailSender>(Emails);
        });
    }
}

public static class TestData
{
    public const string Password = "Passw0rd-long";

    public static string NewEmail(string prefix = "user") => $"{prefix}-{Guid.NewGuid():N}@example.com";

    public static Task<HttpResponseMessage> RegisterAsync(this HttpClient client, string? email, string? password = Password) =>
        client.PostAsJsonAsync("/auth/register", new { email, password });

    public static Task<HttpResponseMessage> ConfirmCodeAsync(this HttpClient client, Guid attemptId, string code) =>
        client.PostAsJsonAsync("/auth/register/confirm", new { attemptId, code });

    public static Task<HttpResponseMessage> ConfirmTokenAsync(this HttpClient client, string token) =>
        client.PostAsJsonAsync("/auth/register/confirm", new { token });

    public static Task<HttpResponseMessage> ResendAsync(this HttpClient client, string email) =>
        client.PostAsJsonAsync("/auth/register/resend", new { email });

    /// <summary>A 6-digit code that differs from <paramref name="code"/>.</summary>
    public static string WrongCode(string code) => code == "000000" ? "111111" : "000000";
}
