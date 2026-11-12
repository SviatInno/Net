using System.Net;
using System.Net.Http.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Security;
using FEDept.BackendCourse.GroupA1.Api.Template.Tests.Infrastructure;
using FEDept.BackendCourse.GroupA1.Api.Template.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Registration;

[Collection(PostgresCollection.Name)]
public sealed class RegistrationWithoutConfirmationTests(PostgresFixture postgres) : IAsyncLifetime
{
    private readonly ApiFactory _api = ApiFactory.Create(postgres, confirmation: false);
    private HttpClient _client = null!;

    public Task InitializeAsync()
    {
        _client = _api.CreateApiClient();
        return Task.CompletedTask;
    }

    public async Task DisposeAsync() => await _api.DisposeAsync();

    [Fact]
    public async Task Register_Returns201WithActiveUser_AndStoresOnlySlowHash()
    {
        var email = TestData.NewEmail();

        using var response = await _client.RegisterAsync(email);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var raw = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain(TestData.Password, raw);
        Assert.DoesNotContain("hash", raw, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("token", raw, StringComparison.OrdinalIgnoreCase);

        var body = await response.Content.ReadFromJsonAsync<UserBody>();
        Assert.Equal(email, body!.Email);
        Assert.Equal("active", body.Status);

        var user = await _api.WithDbAsync(db => db.Users.SingleAsync(u => u.Id == body.Id));
        Assert.Equal(UserStatus.Active, user.Status);
        Assert.StartsWith("$argon2id$", user.PasswordHash);
        Assert.DoesNotContain(TestData.Password, user.PasswordHash);
        Assert.Empty(_api.Emails.Sent);
        Assert.False(await _api.WithDbAsync(db => db.RegistrationChallenges.AnyAsync(c => c.UserId == user.Id)));
    }

    [Fact]
    public async Task Register_NormalizesEmail_AndRejectsDuplicateWith409()
    {
        var email = TestData.NewEmail();

        using var first = await _client.RegisterAsync($"  {email.ToUpperInvariant()} ");
        using var second = await _client.RegisterAsync(email);

        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        Assert.Equal(email, (await first.Content.ReadFromJsonAsync<UserBody>())!.Email);
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
        Assert.Equal("email_taken", (await second.Content.ReadFromJsonAsync<ProblemBody>())!.Code);
    }

    [Fact]
    public async Task Register_TreatsPlusTagAsSeparateAddress()
    {
        var local = $"user{Guid.NewGuid():N}";

        using var plain = await _client.RegisterAsync($"{local}@example.com");
        using var tagged = await _client.RegisterAsync($"{local}+tag@example.com");

        Assert.Equal(HttpStatusCode.Created, plain.StatusCode);
        Assert.Equal(HttpStatusCode.Created, tagged.StatusCode);
    }

    [Fact]
    public async Task Register_KeepsPasswordWhitespace_AndSaltsEveryHash()
    {
        const string password = "  pass word1  ";
        using var first = await _client.RegisterAsync(TestData.NewEmail(), password);
        using var second = await _client.RegisterAsync(TestData.NewEmail(), password);
        var ids = new[]
        {
            (await first.Content.ReadFromJsonAsync<UserBody>())!.Id,
            (await second.Content.ReadFromJsonAsync<UserBody>())!.Id,
        };

        var hashes = await _api.WithDbAsync(db =>
            db.Users.Where(u => ids.Contains(u.Id)).Select(u => u.PasswordHash).ToListAsync());

        var hasher = _api.Services.GetRequiredService<IPasswordHasher>();
        Assert.NotEqual(hashes[0], hashes[1]);
        Assert.All(hashes, h => Assert.True(hasher.Verify(password, h)));
        Assert.All(hashes, h => Assert.False(hasher.Verify(password.Trim(), h)));
    }

    [Fact]
    public async Task Register_AcceptsLettersOfAnyAlphabet()
    {
        using var response = await _client.RegisterAsync(TestData.NewEmail(), "секрет12");

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("plainaddress")]
    [InlineData("user@localhost")]
    [InlineData("user@@example.com")]
    [InlineData("us er@example.com")]
    [InlineData("Name <user@example.com>")]
    [InlineData("user@example..com")]
    public async Task Register_RejectsInvalidEmail(string? email)
    {
        using var response = await _client.RegisterAsync(email);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var problem = await response.Content.ReadFromJsonAsync<ProblemBody>();
        Assert.Equal("validation_failed", problem!.Code);
        Assert.Contains("email", problem.Errors!.Keys);
    }

    public static TheoryData<string?> InvalidPasswords => new()
    {
        null,
        "",
        "short1a",                          // 7 characters
        "abcdefgh",                         // no digit
        "12345678",                         // no letter
        new string('a', 128) + "1",         // 129 characters: too long, never truncated
    };

    [Theory]
    [MemberData(nameof(InvalidPasswords))]
    public async Task Register_RejectsPasswordPolicyViolations(string? password)
    {
        var email = TestData.NewEmail();

        using var response = await _client.RegisterAsync(email, password);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var problem = await response.Content.ReadFromJsonAsync<ProblemBody>();
        Assert.Contains("password", problem!.Errors!.Keys);
        Assert.False(await _api.WithDbAsync(db => db.Users.AnyAsync(u => u.Email == email)));
    }

    [Fact]
    public async Task Register_ConcurrentSameEmail_CreatesOneUser_OthersGet409()
    {
        var email = TestData.NewEmail();

        var responses = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => _client.RegisterAsync(email)));

        Assert.Single(responses, r => r.StatusCode == HttpStatusCode.Created);
        Assert.All(responses.Where(r => r.StatusCode != HttpStatusCode.Created),
            r => Assert.Equal(HttpStatusCode.Conflict, r.StatusCode));
        Assert.Equal(1, await _api.WithDbAsync(db => db.Users.CountAsync(u => u.Email == email)));
    }

    [Fact]
    public async Task Register_DoesNotWritePasswordOrHashToLogs()
    {
        const string password = "Unique-Pa55word-for-logs";
        var email = TestData.NewEmail();

        using var response = await _client.RegisterAsync(email, password);
        using var duplicate = await _client.RegisterAsync(email, password);
        var hash = await _api.WithDbAsync(db => db.Users.Where(u => u.Email == email).Select(u => u.PasswordHash).SingleAsync());

        Assert.Contains(_api.Logs.Entries, e => e.Contains("Registration succeeded"));
        Assert.Contains(_api.Logs.Entries, e => e.Contains("email_taken"));
        Assert.DoesNotContain(_api.Logs.Entries, e => e.Contains(password) || e.Contains(hash));
    }

    [Fact]
    public async Task Register_MalformedJson_Returns400()
    {
        using var content = new StringContent("{ not json", System.Text.Encoding.UTF8, "application/json");

        using var response = await _client.PostAsync("/auth/register", content);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}
