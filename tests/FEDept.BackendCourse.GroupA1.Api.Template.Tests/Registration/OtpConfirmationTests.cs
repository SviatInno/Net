using System.Net;
using System.Net.Http.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Tests.Infrastructure;
using FEDept.BackendCourse.GroupA1.Api.Template.Users;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Registration;

[Collection(PostgresCollection.Name)]
public sealed class OtpConfirmationTests(PostgresFixture postgres) : IAsyncLifetime
{
    private readonly ApiFactory _api = ApiFactory.Create(postgres, confirmation: true, method: "Otp");
    private HttpClient _client = null!;

    public Task InitializeAsync()
    {
        _client = _api.CreateApiClient();
        return Task.CompletedTask;
    }

    public async Task DisposeAsync() => await _api.DisposeAsync();

    [Fact]
    public async Task Register_Returns202WithoutSecret_KeepsUserPending_AndOccupiesEmail()
    {
        var email = TestData.NewEmail();

        using var response = await _client.RegisterAsync(email);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        var raw = await response.Content.ReadAsStringAsync();
        var body = await response.Content.ReadFromJsonAsync<PendingBody>();
        Assert.Equal(new PendingBody(true, "otp", body!.AttemptId, 600, 60), body);

        var code = _api.Emails.LastCodeFor(email);
        Assert.Matches(@"^\d{6}$", code);
        Assert.DoesNotContain(code, raw);

        var challenge = await _api.WithDbAsync(db => db.RegistrationChallenges.Include(c => c.User).SingleAsync(c => c.Id == body.AttemptId));
        Assert.Equal(UserStatus.Pending, challenge.User.Status);
        Assert.Equal(32, challenge.SecretHash.Length);
        Assert.Equal(challenge.LastSentAt.AddMinutes(10), challenge.ExpiresAt);

        using var again = await _client.RegisterAsync(email);
        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
    }

    [Fact]
    public async Task Confirm_WithCorrectCode_ActivatesUser_AndConsumesAttempt()
    {
        var (email, attemptId) = await RegisterAsync();
        var code = _api.Emails.LastCodeFor(email);

        using var response = await _client.ConfirmCodeAsync(attemptId, code);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var user = await response.Content.ReadFromJsonAsync<UserBody>();
        Assert.Equal(email, user!.Email);
        Assert.Equal("active", user.Status);

        using var reuse = await _client.ConfirmCodeAsync(attemptId, code);
        Assert.Equal(HttpStatusCode.BadRequest, reuse.StatusCode);
        Assert.Equal("invalid_confirmation", (await reuse.Content.ReadFromJsonAsync<ProblemBody>())!.Code);
    }

    [Fact]
    public async Task Confirm_FifthAttemptCanStillSucceed()
    {
        var (email, attemptId) = await RegisterAsync();
        var code = _api.Emails.LastCodeFor(email);

        for (var i = 0; i < 4; i++)
        {
            using var wrong = await _client.ConfirmCodeAsync(attemptId, TestData.WrongCode(code));
            Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
        }

        using var response = await _client.ConfirmCodeAsync(attemptId, code);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Confirm_AfterFiveWrongCodes_RejectsEvenCorrectCodeWith429()
    {
        var (email, attemptId) = await RegisterAsync();
        var code = _api.Emails.LastCodeFor(email);

        for (var i = 0; i < 5; i++)
        {
            using var wrong = await _client.ConfirmCodeAsync(attemptId, TestData.WrongCode(code));
            Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode); // the 5th wrong one is still "wrong code"
        }

        using var response = await _client.ConfirmCodeAsync(attemptId, code);

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.Equal("attempts_exhausted", (await response.Content.ReadFromJsonAsync<ProblemBody>())!.Code);
        var challenge = await _api.WithDbAsync(db => db.RegistrationChallenges.SingleAsync(c => c.Id == attemptId));
        Assert.Equal(5, challenge.Attempts);
        Assert.NotNull(challenge.ConsumedAt);
    }

    [Fact]
    public async Task Confirm_ExpiredCode_Returns400_WithoutCountingAttempt()
    {
        var (email, attemptId) = await RegisterAsync();
        var code = _api.Emails.LastCodeFor(email);
        _api.Time.Advance(TimeSpan.FromMinutes(10));

        using var response = await _client.ConfirmCodeAsync(attemptId, code);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var challenge = await _api.WithDbAsync(db => db.RegistrationChallenges.Include(c => c.User).SingleAsync(c => c.Id == attemptId));
        Assert.Equal(0, challenge.Attempts);
        Assert.Null(challenge.ConsumedAt);
        Assert.Equal(UserStatus.Pending, challenge.User.Status);
    }

    [Fact]
    public async Task Confirm_UnknownAttempt_Returns400()
    {
        using var response = await _client.ConfirmCodeAsync(Guid.NewGuid(), "123456");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_confirmation", (await response.Content.ReadFromJsonAsync<ProblemBody>())!.Code);
    }

    [Theory]
    [InlineData("12345")]
    [InlineData("1234567")]
    [InlineData("12a456")]
    public async Task Confirm_MalformedCode_Returns400_WithoutCountingAttempt(string code)
    {
        var (_, attemptId) = await RegisterAsync();

        using var response = await _client.ConfirmCodeAsync(attemptId, code);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("validation_failed", (await response.Content.ReadFromJsonAsync<ProblemBody>())!.Code);
        Assert.Equal(0, await _api.WithDbAsync(db => db.RegistrationChallenges.Where(c => c.Id == attemptId).Select(c => c.Attempts).SingleAsync()));
    }

    [Fact]
    public async Task Confirm_WithoutAttemptIdOrCode_Returns400()
    {
        using var response = await _client.PostAsJsonAsync("/auth/register/confirm", new { });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("validation_failed", (await response.Content.ReadFromJsonAsync<ProblemBody>())!.Code);
    }

    [Fact]
    public async Task Resend_Within60Seconds_Returns429WithRetryAfter()
    {
        var (email, _) = await RegisterAsync();
        _api.Time.Advance(TimeSpan.FromSeconds(59));

        using var response = await _client.ResendAsync(email);

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.Equal("resend_too_early", (await response.Content.ReadFromJsonAsync<ProblemBody>())!.Code);
        Assert.Equal(TimeSpan.FromSeconds(1), response.Headers.RetryAfter!.Delta);
        Assert.Single(_api.Emails.Sent, m => m.To == email);
    }

    [Fact]
    public async Task Resend_ReplacesCode_RestartsTtl_AndResetsExhaustedAttempts()
    {
        var (email, attemptId) = await RegisterAsync();
        var oldCode = _api.Emails.LastCodeFor(email);
        for (var i = 0; i < 5; i++)
        {
            (await _client.ConfirmCodeAsync(attemptId, TestData.WrongCode(oldCode))).Dispose();
        }

        _api.Time.Advance(TimeSpan.FromMinutes(9));

        using var resend = await _client.ResendAsync(email);

        Assert.Equal(HttpStatusCode.Accepted, resend.StatusCode);
        var body = await resend.Content.ReadFromJsonAsync<PendingBody>();
        Assert.Equal(new PendingBody(true, "otp", attemptId, 600, 60), body);
        var newCode = _api.Emails.LastCodeFor(email);
        Assert.DoesNotContain(newCode, await resend.Content.ReadAsStringAsync());

        // The new code lives a full TTL from the resend, the old one is dead.
        _api.Time.Advance(TimeSpan.FromMinutes(9));
        if (newCode != oldCode)
        {
            using var old = await _client.ConfirmCodeAsync(attemptId, oldCode);
            Assert.Equal(HttpStatusCode.BadRequest, old.StatusCode);
        }

        using var confirm = await _client.ConfirmCodeAsync(attemptId, newCode);
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);
    }

    [Fact]
    public async Task Resend_WithoutPendingRegistration_Returns400()
    {
        var (email, attemptId) = await RegisterAsync();
        (await _client.ConfirmCodeAsync(attemptId, _api.Emails.LastCodeFor(email))).Dispose();
        _api.Time.Advance(TimeSpan.FromMinutes(2));

        using var active = await _client.ResendAsync(email);
        using var unknown = await _client.ResendAsync(TestData.NewEmail());
        using var invalid = await _client.ResendAsync("not-an-email");

        Assert.Equal(HttpStatusCode.BadRequest, active.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
    }

    [Fact]
    public async Task Register_WhenSmtpFails_Returns503_KeepsPending_ThenResendDelivers()
    {
        var email = TestData.NewEmail();
        _api.Emails.Fail = true;

        using var response = await _client.RegisterAsync(email);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("email_delivery_failed", (await response.Content.ReadFromJsonAsync<ProblemBody>())!.Code);
        var challenge = await _api.WithDbAsync(db => db.RegistrationChallenges.Include(c => c.User).SingleAsync(c => c.User.Email == email));
        Assert.Equal(UserStatus.Pending, challenge.User.Status);

        _api.Emails.Fail = false;
        using var again = await _client.RegisterAsync(email);
        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);

        _api.Time.Advance(TimeSpan.FromSeconds(60));
        using var resend = await _client.ResendAsync(email);
        Assert.Equal(HttpStatusCode.Accepted, resend.StatusCode);

        using var confirm = await _client.ConfirmCodeAsync(challenge.Id, _api.Emails.LastCodeFor(email));
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);
    }

    [Fact]
    public async Task Confirm_ConcurrentWrongCodes_EveryRejectionIsCounted()
    {
        var (email, attemptId) = await RegisterAsync();
        var wrong = TestData.WrongCode(_api.Emails.LastCodeFor(email));

        var responses = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => _client.ConfirmCodeAsync(attemptId, wrong)));

        // A "wrong code" answer is only given after its attempt has been persisted,
        // so parallel guessing cannot get more than 5 verdicts.
        var wrongVerdicts = responses.Count(r => r.StatusCode == HttpStatusCode.BadRequest);
        Assert.All(responses, r => Assert.True(
            r.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.TooManyRequests, r.StatusCode.ToString()));
        Assert.Equal(5, wrongVerdicts);
        Assert.Equal(5, await _api.WithDbAsync(db => db.RegistrationChallenges.Where(c => c.Id == attemptId).Select(c => c.Attempts).SingleAsync()));
    }

    [Fact]
    public async Task Logs_ContainAuditEvents_ButNoPasswordOrCode()
    {
        var (email, attemptId) = await RegisterAsync();
        var code = _api.Emails.LastCodeFor(email);
        (await _client.ConfirmCodeAsync(attemptId, TestData.WrongCode(code))).Dispose();
        (await _client.ConfirmCodeAsync(attemptId, code)).Dispose();

        var logs = _api.Logs.Entries;
        Assert.Contains(logs, e => e.Contains("Confirmation email sent"));
        Assert.Contains(logs, e => e.Contains("wrong_secret"));
        Assert.Contains(logs, e => e.Contains("Registration confirmed"));
        Assert.DoesNotContain(logs, e => e.Contains(TestData.Password) || e.Contains(code));
    }

    private async Task<(string Email, Guid AttemptId)> RegisterAsync()
    {
        var email = TestData.NewEmail();
        using var response = await _client.RegisterAsync(email);
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        return (email, (await response.Content.ReadFromJsonAsync<PendingBody>())!.AttemptId);
    }
}
