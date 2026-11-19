using System.Net;
using System.Net.Http.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Features.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Tests.Infrastructure;
using FEDept.BackendCourse.GroupA1.Api.Template.Users;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Authentication;

/// <summary>Login with an emailed one-time code: sections 1.3.1 (steps 6–8) and 1.3.2.</summary>
[Collection(PostgresCollection.Name)]
public sealed class OtpLoginTests(PostgresFixture postgres) : IAsyncLifetime
{
    private readonly ApiFactory _api = ApiFactory.CreateForLogin(postgres, confirmation: true, method: "otp");
    private HttpClient _client = null!;

    public Task InitializeAsync()
    {
        _client = _api.CreateCookielessClient();
        return Task.CompletedTask;
    }

    public async Task DisposeAsync() => await _api.DisposeAsync();

    [Fact]
    public async Task Login_Returns202WithAttempt_NoCookies_AndSendsCodeByEmailOnly()
    {
        var email = await _client.CreateActiveUserAsync();

        using var response = await _client.LoginAsync(email);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Empty(response.SetCookies());
        var raw = await response.Content.ReadAsStringAsync();
        var body = await response.Content.ReadFromJsonAsync<LoginPendingBody>();
        Assert.Equal(new LoginPendingBody(true, "otp", body!.AttemptId, 600, 60), body);

        var code = _api.Emails.LastCodeFor(email);
        Assert.Matches(@"^\d{6}$", code);
        Assert.DoesNotContain(code, raw);

        var challenge = await FindAsync(body.AttemptId);
        Assert.Equal(32, challenge.SecretHash.Length);
        Assert.Null(challenge.ConsumedAt);
    }

    [Fact]
    public async Task Confirm_WithCorrectCode_Returns204WithCookies_AndConsumesAttempt()
    {
        var (email, attemptId) = await LoginAsync();
        var code = _api.Emails.LastCodeFor(email);

        using var response = await _client.ConfirmLoginCodeAsync(attemptId, code);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsByteArrayAsync());
        var cookies = response.AuthCookies();
        using var me = await _client.MeAsync(cookies.AccessToken);
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        Assert.Equal(LoginChallengeConsumedReason.Confirmed, (await FindAsync(attemptId)).ConsumedReason);

        using var reuse = await _client.ConfirmLoginCodeAsync(attemptId, code);
        Assert.Equal(HttpStatusCode.BadRequest, reuse.StatusCode);
        Assert.Equal("invalid_confirmation", (await reuse.ProblemAsync()).Code);
    }

    [Fact]
    public async Task Confirm_FifthEntryIsStillChecked_AndCanSucceed()
    {
        var (email, attemptId) = await LoginAsync();
        var code = _api.Emails.LastCodeFor(email);

        for (var i = 0; i < 4; i++)
        {
            using var wrong = await _client.ConfirmLoginCodeAsync(attemptId, TestData.WrongCode(code));
            Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
        }

        using var response = await _client.ConfirmLoginCodeAsync(attemptId, code);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    [Fact]
    public async Task Confirm_FifthWrongCode_Returns400AndExhausts_ThenEverythingIs429()
    {
        var (email, attemptId) = await LoginAsync();
        var code = _api.Emails.LastCodeFor(email);

        for (var i = 0; i < 5; i++)
        {
            using var wrong = await _client.ConfirmLoginCodeAsync(attemptId, TestData.WrongCode(code));
            Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
            Assert.Equal("invalid_confirmation", (await wrong.ProblemAsync()).Code);
        }

        var challenge = await FindAsync(attemptId);
        Assert.Equal(5, challenge.Attempts);
        Assert.Equal(LoginChallengeConsumedReason.AttemptsExhausted, challenge.ConsumedReason);

        using var correct = await _client.ConfirmLoginCodeAsync(attemptId, code);
        Assert.Equal(HttpStatusCode.TooManyRequests, correct.StatusCode);
        Assert.Equal("attempts_exhausted", (await correct.ProblemAsync()).Code);

        _api.Time.Advance(TimeSpan.FromSeconds(61));
        using var resend = await _client.ResendLoginAsync(attemptId);
        Assert.Equal(HttpStatusCode.TooManyRequests, resend.StatusCode);
        Assert.Equal("attempts_exhausted", (await resend.ProblemAsync()).Code);

        // An exhausted attempt is not "open": a new login starts a new one right away.
        using var again = await _client.LoginAsync(email);
        Assert.Equal(HttpStatusCode.Accepted, again.StatusCode);
    }

    [Fact]
    public async Task Confirm_ExpiredCode_Returns400_WithoutCountingAttempt()
    {
        var (email, attemptId) = await LoginAsync();
        var code = _api.Emails.LastCodeFor(email);
        _api.Time.Advance(TimeSpan.FromMinutes(10));

        using var response = await _client.ConfirmLoginCodeAsync(attemptId, code);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var challenge = await FindAsync(attemptId);
        Assert.Equal(0, challenge.Attempts);
        Assert.Null(challenge.ConsumedAt);
    }

    [Theory]
    [InlineData("12345")]
    [InlineData("1234567")]
    [InlineData("12a456")]
    public async Task Confirm_MalformedCode_Returns400ValidationFailed_WithoutCountingAttempt(string code)
    {
        var (_, attemptId) = await LoginAsync();

        using var response = await _client.ConfirmLoginCodeAsync(attemptId, code);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("validation_failed", (await response.ProblemAsync()).Code);
        Assert.Equal(0, (await FindAsync(attemptId)).Attempts);
    }

    [Fact]
    public async Task Confirm_UnknownAttempt_Returns400()
    {
        using var response = await _client.ConfirmLoginCodeAsync(Guid.NewGuid(), "123456");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_confirmation", (await response.ProblemAsync()).Code);
    }

    [Fact]
    public async Task Login_Within60Seconds_Returns429_WithoutNewAttemptOrEmail()
    {
        var (email, attemptId) = await LoginAsync();
        _api.Time.Advance(TimeSpan.FromSeconds(45));

        using var response = await _client.LoginAsync(email);

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        var problem = await response.ProblemAsync();
        Assert.Equal("resend_too_early", problem.Code);
        Assert.Equal(15, problem.RetryAfterSeconds);
        Assert.Equal(TimeSpan.FromSeconds(15), response.Headers.RetryAfter!.Delta);
        Assert.Single(_api.Emails.Sent, m => m.To == email);
        Assert.Equal(1, await CountAttemptsAsync(email));
        Assert.Null((await FindAsync(attemptId)).ConsumedAt);
    }

    [Fact]
    public async Task Login_After60Seconds_ReplacesPreviousAttempt()
    {
        var (email, oldAttemptId) = await LoginAsync();
        var oldCode = _api.Emails.LastCodeFor(email);
        _api.Time.Advance(TimeSpan.FromSeconds(60));

        var (_, newAttemptId) = await LoginAsync(email);

        Assert.NotEqual(oldAttemptId, newAttemptId);
        Assert.Equal(LoginChallengeConsumedReason.Replaced, (await FindAsync(oldAttemptId)).ConsumedReason);
        using var old = await _client.ConfirmLoginCodeAsync(oldAttemptId, oldCode);
        Assert.Equal(HttpStatusCode.BadRequest, old.StatusCode);
        using var confirm = await _client.ConfirmLoginCodeAsync(newAttemptId, _api.Emails.LastCodeFor(email));
        Assert.Equal(HttpStatusCode.NoContent, confirm.StatusCode);
    }

    [Fact]
    public async Task Resend_Within60Seconds_Returns429WithRemainingTime()
    {
        var (email, attemptId) = await LoginAsync();
        _api.Time.Advance(TimeSpan.FromSeconds(59));

        using var response = await _client.ResendLoginAsync(attemptId);

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.Equal("resend_too_early", (await response.ProblemAsync()).Code);
        Assert.Equal(TimeSpan.FromSeconds(1), response.Headers.RetryAfter!.Delta);
        Assert.Single(_api.Emails.Sent, m => m.To == email);
    }

    [Fact]
    public async Task Resend_ReplacesCode_RestartsTtl_AndResetsAttempts_EvenAfterExpiry()
    {
        var (email, attemptId) = await LoginAsync();
        var oldCode = _api.Emails.LastCodeFor(email);
        for (var i = 0; i < 3; i++)
        {
            (await _client.ConfirmLoginCodeAsync(attemptId, TestData.WrongCode(oldCode))).Dispose();
        }

        _api.Time.Advance(TimeSpan.FromMinutes(11)); // expired: confirmation impossible, resend still allowed

        using var resend = await _client.ResendLoginAsync(attemptId);

        Assert.Equal(HttpStatusCode.Accepted, resend.StatusCode);
        Assert.Equal(new ResendBody("otp", attemptId, 600, 60), await resend.Content.ReadFromJsonAsync<ResendBody>());
        var newCode = _api.Emails.LastCodeFor(email);
        Assert.DoesNotContain(newCode, await resend.Content.ReadAsStringAsync());
        Assert.Equal(0, (await FindAsync(attemptId)).Attempts);

        _api.Time.Advance(TimeSpan.FromMinutes(9));
        if (newCode != oldCode)
        {
            using var old = await _client.ConfirmLoginCodeAsync(attemptId, oldCode);
            Assert.Equal(HttpStatusCode.BadRequest, old.StatusCode);
        }

        using var confirm = await _client.ConfirmLoginCodeAsync(attemptId, newCode);
        Assert.Equal(HttpStatusCode.NoContent, confirm.StatusCode);
    }

    [Fact]
    public async Task Resend_ConfirmedOrUnknownOrMalformedAttempt_Returns400()
    {
        var (email, attemptId) = await LoginAsync();
        (await _client.ConfirmLoginCodeAsync(attemptId, _api.Emails.LastCodeFor(email))).Dispose();
        _api.Time.Advance(TimeSpan.FromMinutes(2));

        using var confirmed = await _client.ResendLoginAsync(attemptId);
        using var unknown = await _client.ResendLoginAsync(Guid.NewGuid());
        using var malformed = await _client.PostAsJsonAsync("/auth/login/resend", new { attemptId = "nope" });

        Assert.Equal(HttpStatusCode.BadRequest, confirmed.StatusCode);
        Assert.Equal("invalid_confirmation", (await confirmed.ProblemAsync()).Code);
        Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
        Assert.Equal("validation_failed", (await malformed.ProblemAsync()).Code);
    }

    [Theory]
    [InlineData(UserStatus.Blocked)]
    [InlineData(UserStatus.Deleting)]
    public async Task Confirm_WhenUserStoppedBeingActive_Returns401_AndConsumesAttempt(UserStatus status)
    {
        var (email, attemptId) = await LoginAsync();
        var code = _api.Emails.LastCodeFor(email);
        await _api.WithDbAsync(db => db.Users.Where(u => u.Email == email)
            .ExecuteUpdateAsync(u => u.SetProperty(x => x.Status, status)));

        using var response = await _client.ConfirmLoginCodeAsync(attemptId, code);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("invalid_credentials", (await response.ProblemAsync()).Code);
        Assert.Empty(response.SetCookies());
        Assert.Equal(LoginChallengeConsumedReason.UserInactive, (await FindAsync(attemptId)).ConsumedReason);

        using var again = await _client.ConfirmLoginCodeAsync(attemptId, code);
        Assert.Equal(HttpStatusCode.BadRequest, again.StatusCode);
        _api.Time.Advance(TimeSpan.FromSeconds(61));
        using var resend = await _client.ResendLoginAsync(attemptId);
        Assert.Equal(HttpStatusCode.BadRequest, resend.StatusCode);
    }

    [Fact]
    public async Task Login_WhenSmtpFails_Returns503WithAttempt_ButNoSecret_ThenResendDelivers()
    {
        var email = await _client.CreateActiveUserAsync();
        _api.Emails.Fail = true;

        using var response = await _client.LoginAsync(email);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var problem = await response.ProblemAsync();
        Assert.Equal("email_delivery_failed", problem.Code);
        Assert.True(problem.ConfirmationRequired);
        Assert.Equal("otp", problem.Method);
        Assert.Equal(60, problem.RetryAfterSeconds);
        var attemptId = problem.AttemptId!.Value;
        Assert.Null((await FindAsync(attemptId)).ConsumedAt);

        _api.Emails.Fail = false;
        _api.Time.Advance(TimeSpan.FromSeconds(60));
        using var resend = await _client.ResendLoginAsync(attemptId);
        Assert.Equal(HttpStatusCode.Accepted, resend.StatusCode);
        using var confirm = await _client.ConfirmLoginCodeAsync(attemptId, _api.Emails.LastCodeFor(email));
        Assert.Equal(HttpStatusCode.NoContent, confirm.StatusCode);
    }

    [Fact]
    public async Task Resend_WhenSmtpFails_Returns503_AndOldCodeStaysDead()
    {
        var (email, attemptId) = await LoginAsync();
        var oldCode = _api.Emails.LastCodeFor(email);
        _api.Time.Advance(TimeSpan.FromSeconds(60));
        _api.Emails.Fail = true;

        using var response = await _client.ResendLoginAsync(attemptId);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("email_delivery_failed", (await response.ProblemAsync()).Code);
        using var old = await _client.ConfirmLoginCodeAsync(attemptId, oldCode);
        Assert.Equal(HttpStatusCode.BadRequest, old.StatusCode);
    }

    [Fact]
    public async Task Confirm_ConcurrentWrongCodes_EveryRejectionIsCounted()
    {
        var (email, attemptId) = await LoginAsync();
        var wrong = TestData.WrongCode(_api.Emails.LastCodeFor(email));

        var responses = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => _client.ConfirmLoginCodeAsync(attemptId, wrong)));

        // Row locks serialize the guesses: exactly five verdicts, then 429.
        Assert.Equal(5, responses.Count(r => r.StatusCode == HttpStatusCode.BadRequest));
        Assert.Equal(7, responses.Count(r => r.StatusCode == HttpStatusCode.TooManyRequests));
        Assert.Equal(5, (await FindAsync(attemptId)).Attempts);
    }

    [Fact]
    public async Task Logs_ContainChallengeEvents_ButNoCodeOrEmail()
    {
        var (email, attemptId) = await LoginAsync();
        var code = _api.Emails.LastCodeFor(email);
        (await _client.ConfirmLoginCodeAsync(attemptId, TestData.WrongCode(code))).Dispose();
        (await _client.ConfirmLoginCodeAsync(attemptId, code)).Dispose();

        var logs = _api.Logs.Entries;
        Assert.Contains(logs, e => e.Contains("Login challenge created") && e.Contains(attemptId.ToString()));
        Assert.Contains(logs, e => e.Contains("Login challenge email sent"));
        Assert.Contains(logs, e => e.Contains("Login challenge rejected") && e.Contains("wrong_secret"));
        Assert.Contains(logs, e => e.Contains("Login challenge confirmed"));
        Assert.DoesNotContain(logs, e => e.Contains(email) || e.Contains(TestData.Password) || e.Contains($" {code}"));
    }

    private async Task<(string Email, Guid AttemptId)> LoginAsync(string? email = null)
    {
        email ??= await _client.CreateActiveUserAsync();
        using var response = await _client.LoginAsync(email);
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        return (email, (await response.Content.ReadFromJsonAsync<LoginPendingBody>())!.AttemptId);
    }

    private Task<LoginChallenge> FindAsync(Guid attemptId) =>
        _api.WithDbAsync(db => db.LoginChallenges.AsNoTracking().SingleAsync(c => c.Id == attemptId));

    private Task<int> CountAttemptsAsync(string email) =>
        _api.WithDbAsync(db => db.LoginChallenges.CountAsync(c => db.Users.Any(u => u.Id == c.UserId && u.Email == email)));
}
