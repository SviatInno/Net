namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Authentication;

public enum AuthErrorKind
{
    /// <summary>400 validation_failed: malformed login, confirm or resend body.</summary>
    Validation,

    /// <summary>400 invalid_confirmation: wrong/expired code or link; unknown, replaced or consumed attempt.</summary>
    InvalidConfirmation,

    /// <summary>401 invalid_credentials: one neutral answer for unknown email, wrong password and non-active user.</summary>
    InvalidCredentials,

    /// <summary>401 invalid_session: refresh token missing, invalid, expired or for a non-active user.</summary>
    InvalidSession,

    /// <summary>429 rate_limited: too many failed password checks for this email and IP.</summary>
    RateLimited,

    /// <summary>429 resend_too_early: a code or link was sent less than 60 seconds ago.</summary>
    ResendTooEarly,

    /// <summary>429 attempts_exhausted: five wrong codes consumed the attempt.</summary>
    AttemptsExhausted,

    /// <summary>503 email_delivery_failed: SMTP refused; the attempt is kept.</summary>
    EmailDeliveryFailed,

    /// <summary>503 token_issue_failed: signing failed; no cookie was written.</summary>
    TokenIssueFailed,

    /// <summary>503 service_unavailable: the attempt transaction was not committed.</summary>
    ServiceUnavailable,
}

public sealed record AuthError(
    AuthErrorKind Kind,
    string Detail,
    IDictionary<string, string[]>? Errors = null,
    TimeSpan? RetryAfter = null,
    IReadOnlyDictionary<string, object?>? Extensions = null);

/// <summary>Success value or error, never both.</summary>
public sealed class AuthResult<T>
    where T : class
{
    private AuthResult(T? value, AuthError? error) => (Value, Error) = (value, error);

    public T? Value { get; }

    public AuthError? Error { get; }

    public static implicit operator AuthResult<T>(T value) => new(value, null);

    public static implicit operator AuthResult<T>(AuthError error) => new(null, error);
}

/// <summary>Login either authenticated the user directly or started an email challenge.</summary>
public sealed record LoginOutcome(TokenPair? Tokens, LoginPendingResponse? Pending);
