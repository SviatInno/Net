namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Registration;

public enum RegistrationErrorKind
{
    /// <summary>400: invalid email, password policy, malformed confirm request.</summary>
    Validation,

    /// <summary>409: email already registered (active or pending).</summary>
    EmailTaken,

    /// <summary>400: wrong/expired code or token, unknown or consumed attempt, nothing to resend.</summary>
    InvalidConfirmation,

    /// <summary>429: code attempts exhausted.</summary>
    AttemptsExhausted,

    /// <summary>429: resend earlier than the cooldown.</summary>
    ResendTooEarly,

    /// <summary>429: too many simultaneous attempts on the same challenge.</summary>
    Contended,

    /// <summary>503: SMTP did not accept the email; pending user and challenge are kept.</summary>
    EmailDeliveryFailed,
}

public sealed record RegistrationError(
    RegistrationErrorKind Kind,
    string Detail,
    IDictionary<string, string[]>? Errors = null,
    TimeSpan? RetryAfter = null);

/// <summary>Success value or error, never both.</summary>
public sealed class RegistrationResult<T>
    where T : class
{
    private RegistrationResult(T? value, RegistrationError? error) => (Value, Error) = (value, error);

    public T? Value { get; }

    public RegistrationError? Error { get; }

    public static implicit operator RegistrationResult<T>(T value) => new(value, null);

    public static implicit operator RegistrationResult<T>(RegistrationError error) => new(null, error);
}

/// <summary>Registration either created an active user or is waiting for confirmation.</summary>
public sealed record RegistrationOutcome(RegisteredUserResponse? Created, ConfirmationPendingResponse? Pending);
