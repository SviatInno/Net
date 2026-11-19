using System.Globalization;
using System.Security.Claims;
using System.Text.Encodings.Web;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Authentication;

/// <summary>
/// The single access check (section 1.3.6) behind <c>RequireAuthorization()</c>: the
/// <c>access_token</c> cookie must be a valid access JWT of an existing <c>active</c> user.
/// The principal carries only the user id. Every failure is one <c>401 invalid_session</c>;
/// a database outage propagates and becomes 503.
/// </summary>
public sealed class AccessCookieAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory loggerFactory,
    UrlEncoder encoder,
    TokenService tokens,
    SessionService sessions)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, loggerFactory, encoder)
{
    public const string SchemeName = "AccessCookie";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var validation = await tokens.ValidateAsync(Request.Cookies[AuthCookies.AccessCookie], TokenUse.Access);
        if (validation.UserId is not { } userId)
        {
            Logger.AccessRejected(null, validation.FailureCategory!);
            return AuthenticateResult.Fail(validation.FailureCategory!);
        }

        if (!await sessions.IsActiveAsync(userId, Context.RequestAborted))
        {
            Logger.AccessRejected(userId, "user_inactive");
            return AuthenticateResult.Fail("user_inactive");
        }

        var identity = new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, userId.ToString("D", CultureInfo.InvariantCulture))],
            SchemeName);
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties) =>
        ProblemResponses.WriteAsync(
            Context,
            StatusCodes.Status401Unauthorized,
            "invalid_session",
            "Unauthorized",
            "The session is invalid or has expired. Sign in again.");
}

public static class UserIdClaimsPrincipalExtensions
{
    /// <summary>The verified user id set by <see cref="AccessCookieAuthenticationHandler"/>.</summary>
    public static Guid GetUserId(this ClaimsPrincipal principal) =>
        Guid.Parse(principal.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? throw new InvalidOperationException("The request is not authenticated."));
}
