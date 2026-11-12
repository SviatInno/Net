using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Registration;

public static class RegistrationEndpoints
{
    public const string RegisterRateLimitPolicy = "registration:register";
    public const string ResendRateLimitPolicy = "registration:resend";

    public static IEndpointRouteBuilder MapRegistrationEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/auth/register")
            .WithTags("Registration")
            .AllowAnonymous();

        group.MapPost("", RegisterAsync)
            .WithName("Register")
            .WithSummary("Register a user by email and password")
            .WithDescription(
                "201 with the active user when email confirmation is disabled; " +
                "202 with the confirmation attempt when it is enabled (the code/link is sent by email only).")
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status409Conflict)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable)
            .RequireRateLimiting(RegisterRateLimitPolicy);

        group.MapPost("/confirm", ConfirmAsync)
            .WithName("ConfirmRegistration")
            .WithSummary("Confirm a registration with attemptId + code (OTP) or token (magic link)")
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status429TooManyRequests);

        group.MapPost("/resend", ResendAsync)
            .WithName("ResendRegistrationConfirmation")
            .WithSummary("Send a new code or link; at most once per 60 seconds")
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable)
            .RequireRateLimiting(ResendRateLimitPolicy);

        return app;
    }

    private static async Task<Results<Created<RegisteredUserResponse>, Accepted<ConfirmationPendingResponse>, ProblemHttpResult>> RegisterAsync(
        [FromBody] RegisterRequest request,
        RegistrationService service,
        HttpResponse response,
        CancellationToken cancellationToken)
    {
        var result = await service.RegisterAsync(request, cancellationToken);
        if (result.Error is { } error)
        {
            return ToProblem(error, response);
        }

        return result.Value!.Created is { } created
            ? TypedResults.Created((string?)null, created)
            : TypedResults.Accepted((string?)null, result.Value.Pending!);
    }

    private static async Task<Results<Ok<RegisteredUserResponse>, ProblemHttpResult>> ConfirmAsync(
        [FromBody] ConfirmRegistrationRequest request,
        RegistrationService service,
        HttpResponse response,
        CancellationToken cancellationToken)
    {
        var result = await service.ConfirmAsync(request, cancellationToken);
        return result.Error is { } error ? ToProblem(error, response) : TypedResults.Ok(result.Value!);
    }

    private static async Task<Results<Accepted<ConfirmationPendingResponse>, ProblemHttpResult>> ResendAsync(
        [FromBody] ResendConfirmationRequest request,
        RegistrationService service,
        HttpResponse response,
        CancellationToken cancellationToken)
    {
        var result = await service.ResendAsync(request, cancellationToken);
        return result.Error is { } error ? ToProblem(error, response) : TypedResults.Accepted((string?)null, result.Value!);
    }

    private static ProblemHttpResult ToProblem(RegistrationError error, HttpResponse response)
    {
        var (status, code, title) = error.Kind switch
        {
            RegistrationErrorKind.Validation => (StatusCodes.Status400BadRequest, "validation_failed", "Validation failed"),
            RegistrationErrorKind.EmailTaken => (StatusCodes.Status409Conflict, "email_taken", "Email already registered"),
            RegistrationErrorKind.InvalidConfirmation => (StatusCodes.Status400BadRequest, "invalid_confirmation", "Invalid confirmation"),
            RegistrationErrorKind.AttemptsExhausted => (StatusCodes.Status429TooManyRequests, "attempts_exhausted", "Too many attempts"),
            RegistrationErrorKind.ResendTooEarly => (StatusCodes.Status429TooManyRequests, "resend_too_early", "Resend too early"),
            RegistrationErrorKind.Contended => (StatusCodes.Status429TooManyRequests, "contended", "Too many simultaneous attempts"),
            RegistrationErrorKind.EmailDeliveryFailed => (StatusCodes.Status503ServiceUnavailable, "email_delivery_failed", "Email not sent"),
            _ => throw new ArgumentOutOfRangeException(nameof(error), error.Kind, null),
        };

        if (error.RetryAfter is { } retryAfter)
        {
            response.Headers.RetryAfter = ((int)Math.Ceiling(retryAfter.TotalSeconds)).ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        var problem = error.Errors is null
            ? new ProblemDetails()
            : new HttpValidationProblemDetails(error.Errors);
        problem.Status = status;
        problem.Title = title;
        problem.Detail = error.Detail;
        problem.Extensions["code"] = code;
        return TypedResults.Problem(problem);
    }
}
