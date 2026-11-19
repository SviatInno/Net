using FEDept.BackendCourse.GroupA1.Api.Template.Tests.Infrastructure;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Authentication;

/// <summary>A missing, short or shared key stops the application at startup (section 1.1).</summary>
public sealed class StartupValidationTests
{
    private const string ShortKey = "c2hvcnQta2V5LTE2LWJ5dGU="; // 16 bytes

    public static TheoryData<string, string?, string> InvalidSettings => new()
    {
        { "JWT_ACCESS_SECRET", null, "JWT_ACCESS_SECRET is required" },
        { "JWT_ACCESS_SECRET", "", "JWT_ACCESS_SECRET is required" },
        { "JWT_REFRESH_SECRET", ShortKey, "JWT_REFRESH_SECRET is required" },
        { "LOGIN_CHALLENGE_HMAC_KEY", "not base64 !!", "LOGIN_CHALLENGE_HMAC_KEY is required" },
        { "AUDIT_LOG_HMAC_KEY", null, "AUDIT_LOG_HMAC_KEY is required" },
        { "JWT_REFRESH_SECRET", ApiFactory.JwtAccessSecret, "JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must be different" },
        { "LOGIN_CHALLENGE_HMAC_KEY", ApiFactory.JwtAccessSecret, "JWT_ACCESS_SECRET and LOGIN_CHALLENGE_HMAC_KEY must be different" },
        { "JWT_ISSUER", "", "JWT_ISSUER is required" },
        { "JWT_AUDIENCE", " ", "JWT_AUDIENCE is required" },
        { "LOGIN_EMAIL_CONFIRMATION_METHOD", "sms", "LOGIN_EMAIL_CONFIRMATION_METHOD must be otp or magic_link" },
        { "LOGIN_EMAIL_CONFIRMATION_ENABLED", "maybe", "LOGIN_EMAIL_CONFIRMATION_ENABLED must be true or false" },
        { "LOGIN_MAGIC_LINK_URL", "/relative", "LOGIN_MAGIC_LINK_URL must be an absolute" },
        { "FRONTEND_ORIGIN", "https://app.example.com/path", "FRONTEND_ORIGIN must be an origin" },
        { "FRONTEND_CROSS_SITE", "true", "FRONTEND_CROSS_SITE=true requires FRONTEND_ORIGIN" },
    };

    [Theory]
    [MemberData(nameof(InvalidSettings))]
    public void InvalidSetting_StopsStartup_NamingTheSetting(string key, string? value, string expectedMessage)
    {
        using var api = new ApiFactory("Host=127.0.0.1;Port=1", new Dictionary<string, string?> { [key] = value ?? string.Empty });

        var exception = Assert.ThrowsAny<Exception>(() => api.CreateClient());

        var text = exception.ToString();
        Assert.Contains(expectedMessage, text);
        Assert.DoesNotContain(ApiFactory.JwtAccessSecret, text);
    }

    [Fact]
    public void ValidSettings_Start()
    {
        using var api = new ApiFactory("Host=127.0.0.1;Port=1", new Dictionary<string, string?>());

        using var client = api.CreateClient();
    }
}
