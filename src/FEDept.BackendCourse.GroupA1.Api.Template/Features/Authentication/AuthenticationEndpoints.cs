using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Authentication;

public static class AuthenticationEndpoints
{
    public const string LoginRateLimitPolicy = "auth:login";
    public const string RefreshRateLimitPolicy = "auth:refresh";

    public static IEndpointRouteBuilder MapAuthenticationEndpoints(this IEndpointRouteBuilder app)
    {
        // Prepared at startup, not on the first unknown-email login.
        _ = app.ServiceProvider.GetRequiredService<DummyPasswordHash>();

        var group = app.MapGroup("/auth").WithTags("Authentication");

        group.MapPost("/login", LoginAsync)
            .AllowAnonymous()
            .WithName("Login")
            .WithSummary("Sign in by email and password")
            .WithDescription(
                "204 with access_token and refresh_token HttpOnly cookies when login confirmation is off; " +
                "202 with the attempt when it is on (the code/link goes by email only).")
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable)
            .RequireRateLimiting(LoginRateLimitPolicy);

        group.MapPost("/login/confirm", ConfirmAsync)
            .AllowAnonymous()
            .WithName("ConfirmLogin")
            .WithSummary("Finish sign-in with attemptId + code (OTP) or token (magic link)")
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

        group.MapPost("/login/resend", ResendAsync)
            .AllowAnonymous()
            .WithName("ResendLoginConfirmation")
            .WithSummary("Send a new sign-in code or link; at most once per 60 seconds")
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

        group.MapPost("/refresh", RefreshAsync)
            .AllowAnonymous()
            .WithName("RefreshSession")
            .WithSummary("Issue a new token pair from the refresh_token cookie")
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable)
            .RequireRateLimiting(RefreshRateLimitPolicy);

        group.MapPost("/logout", Logout)
            .AllowAnonymous()
            .WithName("Logout")
            .WithSummary("Clear both auth cookies; always 204")
            .ProducesProblem(StatusCodes.Status403Forbidden);

        group.MapGet("/me", (ClaimsPrincipal user) => TypedResults.Ok(new CurrentUserResponse(user.GetUserId())))
            .RequireAuthorization()
            .WithName("GetCurrentUser")
            .WithSummary("The verified id of the signed-in user (access check example)")
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

        return app;
    }

    private static async Task<Results<NoContent, Accepted<LoginPendingResponse>, ProblemHttpResult>> LoginAsync(
        [FromBody] LoginRequest request,
        LoginService service,
        AuthCookies cookies,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        var result = await service.LoginAsync(request, http.Connection.RemoteIpAddress, cancellationToken);
        if (result.Error is { } error)
        {
            return ToProblem(error, http.Response);
        }

        if (result.Value!.Tokens is { } tokens)
        {
            cookies.Set(http.Response, tokens);
            return TypedResults.NoContent();
        }

        return TypedResults.Accepted((string?)null, result.Value.Pending!);
    }

    private static async Task<Results<NoContent, ProblemHttpResult>> ConfirmAsync(
        [FromBody] ConfirmLoginRequest request,
        LoginService service,
        AuthCookies cookies,
        HttpResponse response,
        CancellationToken cancellationToken)
    {
        var result = await service.ConfirmAsync(request, cancellationToken);
        if (result.Error is { } error)
        {
            return ToProblem(error, response);
        }

        cookies.Set(response, result.Value!);
        return TypedResults.NoContent();
    }

    private static async Task<Results<Accepted<LoginResendResponse>, ProblemHttpResult>> ResendAsync(
        [FromBody] ResendLoginRequest request,
        LoginService service,
        HttpResponse response,
        CancellationToken cancellationToken)
    {
        var result = await service.ResendAsync(request, cancellationToken);
        return result.Error is { } error
            ? ToProblem(error, response)
            : TypedResults.Accepted((string?)null, result.Value!);
    }

    // The refresh token is read from its cookie only: body, query and other headers are ignored.
    private static async Task<Results<NoContent, ProblemHttpResult>> RefreshAsync(
        HttpContext http,
        SessionService service,
        AuthCookies cookies,
        CancellationToken cancellationToken)
    {
        var result = await service.RefreshAsync(http.Request.Cookies[AuthCookies.RefreshCookie], cancellationToken);
        if (result.Error is { } error)
        {
            return ToProblem(error, http.Response);
        }

        cookies.Set(http.Response, result.Value!);
        return TypedResults.NoContent();
    }

    // Needs no valid token: always clears this client's cookies. Copies on other devices stay valid until exp.
    private static NoContent Logout(HttpResponse response, AuthCookies cookies, ILoggerFactory loggerFactory)
    {
        cookies.Clear(response);
        loggerFactory.CreateLogger(typeof(AuthenticationEndpoints)).LoggedOut();
        return TypedResults.NoContent();
    }

    private static ProblemHttpResult ToProblem(AuthError error, HttpResponse response)
    {
        var (status, code, title) = error.Kind switch
        {
            AuthErrorKind.Validation => (StatusCodes.Status400BadRequest, "validation_failed", "Validation failed"),
            AuthErrorKind.InvalidConfirmation => (StatusCodes.Status400BadRequest, "invalid_confirmation", "Invalid confirmation"),
            AuthErrorKind.InvalidCredentials => (StatusCodes.Status401Unauthorized, "invalid_credentials", "Invalid credentials"),
            AuthErrorKind.InvalidSession => (StatusCodes.Status401Unauthorized, "invalid_session", "Unauthorized"),
            AuthErrorKind.RateLimited => (StatusCodes.Status429TooManyRequests, "rate_limited", "Too many requests"),
            AuthErrorKind.ResendTooEarly => (StatusCodes.Status429TooManyRequests, "resend_too_early", "Resend too early"),
            AuthErrorKind.AttemptsExhausted => (StatusCodes.Status429TooManyRequests, "attempts_exhausted", "Too many attempts"),
            AuthErrorKind.EmailDeliveryFailed => (StatusCodes.Status503ServiceUnavailable, "email_delivery_failed", "Email not sent"),
            AuthErrorKind.TokenIssueFailed => (StatusCodes.Status503ServiceUnavailable, "token_issue_failed", "Service unavailable"),
            AuthErrorKind.ServiceUnavailable => (StatusCodes.Status503ServiceUnavailable, "service_unavailable", "Service unavailable"),
            _ => throw new ArgumentOutOfRangeException(nameof(error), error.Kind, null),
        };

        if (error.RetryAfter is { } retryAfter)
        {
            response.Headers.RetryAfter = Infrastructure.ProblemResponses.RetryAfterSeconds(retryAfter)
                .ToString(CultureInfo.InvariantCulture);
        }

        var problem = error.Errors is null
            ? new ProblemDetails()
            : new HttpValidationProblemDetails(error.Errors);
        problem.Status = status;
        problem.Title = title;
        problem.Detail = error.Detail;
        problem.Extensions["code"] = code;
        foreach (var (key, value) in error.Extensions ?? new Dictionary<string, object?>())
        {
            problem.Extensions[key] = value;
        }

        return TypedResults.Problem(problem);
    }
}
