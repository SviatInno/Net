using System.Net;
using System.Net.Http.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Tests.Infrastructure;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Registration;

[Collection(PostgresCollection.Name)]
public sealed class RegistrationFlagAndRateLimitTests(PostgresFixture postgres)
{
    [Fact]
    public async Task PendingRegistration_StaysConfirmable_AfterFlagIsTurnedOff()
    {
        var email = TestData.NewEmail();
        Guid attemptId;
        string code;
        await using (var withFlag = ApiFactory.Create(postgres, confirmation: true))
        {
            using var register = await withFlag.CreateApiClient().RegisterAsync(email);
            attemptId = (await register.Content.ReadFromJsonAsync<PendingBody>())!.AttemptId;
            code = withFlag.Emails.LastCodeFor(email);
        }

        await using var withoutFlag = ApiFactory.Create(postgres, confirmation: false);
        var client = withoutFlag.CreateApiClient();

        // Not activated by the flag change: the email is still taken by the pending record.
        using var again = await client.RegisterAsync(email);
        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);

        using var confirm = await client.ConfirmCodeAsync(attemptId, code);
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);

        // New registrations follow the current flag.
        using var fresh = await client.RegisterAsync(TestData.NewEmail());
        Assert.Equal(HttpStatusCode.Created, fresh.StatusCode);
    }

    [Fact]
    public async Task Register_OverConfiguredRate_Returns429()
    {
        await using var api = ApiFactory.Create(postgres, confirmation: false, registerPermits: 2);
        var client = api.CreateApiClient();

        using var first = await client.RegisterAsync(TestData.NewEmail());
        using var second = await client.RegisterAsync("invalid");
        using var third = await client.RegisterAsync(TestData.NewEmail());

        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, second.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, third.StatusCode);
        Assert.Equal("rate_limited", (await third.Content.ReadFromJsonAsync<ProblemBody>())!.Code);
    }
}
