using FEDept.BackendCourse.GroupA1.Api.Template.Data;
using FEDept.BackendCourse.GroupA1.Api.Template.Email;
using FEDept.BackendCourse.GroupA1.Api.Template.Security;
using FEDept.BackendCourse.GroupA1.Api.Template.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Registration;

public sealed class RegistrationService(
    AppDbContext db,
    IPasswordHasher passwordHasher,
    ChallengeSecrets secrets,
    IEmailSender emailSender,
    TimeProvider timeProvider,
    IOptions<RegistrationOptions> options,
    ILogger<RegistrationService> logger)
{
    private const string EmailUniqueIndex = "ux_users_email";

    // Concurrent requests on one challenge are serialized by the optimistic concurrency token.
    // A request never answers before its own wrong attempt is persisted.
    private const int MaxConcurrencyRetries = 5;

    private readonly RegistrationOptions _options = options.Value;

    public async Task<RegistrationResult<RegistrationOutcome>> RegisterAsync(
        RegisterRequest request, CancellationToken cancellationToken)
    {
        var errors = new Dictionary<string, string[]>();
        if (RegistrationValidator.ValidateEmail(request.Email) is { } emailError)
        {
            errors["email"] = [emailError];
        }

        if (RegistrationValidator.ValidatePassword(request.Password) is { } passwordError)
        {
            errors["password"] = [passwordError];
        }

        if (errors.Count > 0)
        {
            logger.RegistrationRejected("validation_failed", string.Join(",", errors.Keys));
            return new RegistrationError(RegistrationErrorKind.Validation, "Registration data is invalid.", errors);
        }

        var email = RegistrationValidator.NormalizeEmail(request.Email!);

        // Cheap pre-check to skip slow hashing; the unique index below is the actual guarantee.
        if (await db.Users.AnyAsync(u => u.Email == email, cancellationToken))
        {
            return EmailTaken();
        }

        var now = timeProvider.GetUtcNow();
        var user = new User
        {
            Id = Guid.CreateVersion7(now),
            Email = email,
            PasswordHash = passwordHasher.Hash(request.Password!),
            Status = _options.ConfirmationEnabled ? UserStatus.Pending : UserStatus.Active,
            CreatedAt = now,
            UpdatedAt = now,
        };
        db.Users.Add(user);

        // RBAC is not connected yet: once it is, the "user" role is assigned here,
        // in the same SaveChanges (transaction) that creates the active user.
        if (!_options.ConfirmationEnabled)
        {
            if (!await TrySaveNewUserAsync(cancellationToken))
            {
                return EmailTaken();
            }

            logger.RegistrationSucceeded(user.Id, "active");
            return new RegistrationOutcome(ToResponse(user), null);
        }

        var method = _options.ConfirmationMethod;
        var secret = ChallengeSecrets.NewSecret(method);
        var challenge = new RegistrationChallenge
        {
            Id = Guid.CreateVersion7(now),
            UserId = user.Id,
            Method = method,
            SecretHash = [],
        };
        challenge.Issue(secrets.Hash(method, secret), now);
        db.RegistrationChallenges.Add(challenge);

        // The pending user and its challenge are committed before the email is sent:
        // if SMTP fails, both stay and the client uses /resend.
        if (!await TrySaveNewUserAsync(cancellationToken))
        {
            return EmailTaken();
        }

        logger.RegistrationSucceeded(user.Id, "pending");

        return await SendChallengeAsync(user, challenge, secret, cancellationToken) is { } deliveryError
            ? deliveryError
            : new RegistrationOutcome(null, ConfirmationPendingResponse.From(challenge));
    }

    public async Task<RegistrationResult<RegisteredUserResponse>> ConfirmAsync(
        ConfirmRegistrationRequest request, CancellationToken cancellationToken)
    {
        if (ValidateConfirmRequest(request) is { } validationError)
        {
            logger.ConfirmationFailed(request.AttemptId, "validation_failed");
            return validationError;
        }

        var method = request.Token is not null ? ConfirmationMethod.MagicLink : ConfirmationMethod.Otp;
        var secret = request.Token ?? request.Code!;

        for (var retry = 0; retry < MaxConcurrencyRetries; retry++)
        {
            db.ChangeTracker.Clear();
            var now = timeProvider.GetUtcNow();

            var challenge = method == ConfirmationMethod.MagicLink
                ? await FindByTokenAsync(secret, cancellationToken)
                : await db.RegistrationChallenges
                    .Include(c => c.User)
                    .FirstOrDefaultAsync(c => c.Id == request.AttemptId && c.Method == ConfirmationMethod.Otp, cancellationToken);

            if (challenge is null)
            {
                logger.ConfirmationFailed(request.AttemptId, "not_found");
                return InvalidConfirmation();
            }

            if (challenge.ConsumedAt is not null)
            {
                logger.ConfirmationFailed(challenge.Id, challenge.IsExhausted ? "attempts_exhausted" : "consumed");
                return challenge.IsExhausted
                    ? new RegistrationError(
                        RegistrationErrorKind.AttemptsExhausted,
                        "Too many wrong codes. Request a new code via /auth/register/resend.")
                    : InvalidConfirmation();
            }

            if (now >= challenge.ExpiresAt)
            {
                // An expired attempt does not consume the counter.
                logger.ConfirmationFailed(challenge.Id, "expired");
                return InvalidConfirmation();
            }

            if (!secrets.Matches(challenge.SecretHash, method, secret))
            {
                challenge.Attempts++;
                if (challenge.Attempts >= RegistrationOptions.MaxCodeAttempts)
                {
                    challenge.ConsumedAt = now;
                }

                challenge.Touch();
                if (!await TrySaveConcurrentAsync(cancellationToken))
                {
                    continue;
                }

                logger.ConfirmationFailed(challenge.Id, "wrong_secret");
                return InvalidConfirmation();
            }

            challenge.ConsumedAt = now;
            challenge.Touch();
            challenge.User.Status = UserStatus.Active;
            challenge.User.UpdatedAt = now;
            // RBAC is not connected yet: once it is, assign the "user" role here (if missing),
            // in the same SaveChanges as the status change.
            if (!await TrySaveConcurrentAsync(cancellationToken))
            {
                continue;
            }

            logger.ConfirmationSucceeded(challenge.Id, challenge.UserId);
            return ToResponse(challenge.User);
        }

        logger.ConfirmationFailed(request.AttemptId, "contended");
        return Contended();
    }

    public async Task<RegistrationResult<ConfirmationPendingResponse>> ResendAsync(
        ResendConfirmationRequest request, CancellationToken cancellationToken)
    {
        if (RegistrationValidator.ValidateEmail(request.Email) is { } emailError)
        {
            logger.ResendRejected("validation_failed");
            return new RegistrationError(
                RegistrationErrorKind.Validation,
                "Resend data is invalid.",
                new Dictionary<string, string[]> { ["email"] = [emailError] });
        }

        var email = RegistrationValidator.NormalizeEmail(request.Email!);

        for (var retry = 0; retry < MaxConcurrencyRetries; retry++)
        {
            db.ChangeTracker.Clear();
            var now = timeProvider.GetUtcNow();

            var challenge = await db.RegistrationChallenges
                .Include(c => c.User)
                .FirstOrDefaultAsync(c => c.User.Email == email, cancellationToken);

            if (challenge is null || challenge.User.Status != UserStatus.Pending)
            {
                logger.ResendRejected("no_pending_registration");
                return new RegistrationError(
                    RegistrationErrorKind.InvalidConfirmation,
                    "There is no registration waiting for confirmation for this email.");
            }

            var nextAllowedAt = challenge.LastSentAt + RegistrationOptions.ResendCooldown;
            if (now < nextAllowedAt)
            {
                logger.ResendRejected("too_early");
                return new RegistrationError(
                    RegistrationErrorKind.ResendTooEarly,
                    "A confirmation email was sent recently. Try again later.",
                    RetryAfter: nextAllowedAt - now);
            }

            // Keeps the challenge's own method: the current flag/method only affects new registrations.
            var secret = ChallengeSecrets.NewSecret(challenge.Method);
            challenge.Issue(secrets.Hash(challenge.Method, secret), now);
            if (!await TrySaveConcurrentAsync(cancellationToken))
            {
                continue; // A parallel resend won; the next round reports "too early".
            }

            return await SendChallengeAsync(challenge.User, challenge, secret, cancellationToken) is { } deliveryError
                ? deliveryError
                : ConfirmationPendingResponse.From(challenge);
        }

        logger.ResendRejected("contended");
        return Contended();
    }

    private async Task<RegistrationChallenge?> FindByTokenAsync(string token, CancellationToken cancellationToken)
    {
        var hash = secrets.Hash(ConfirmationMethod.MagicLink, token);
        return await db.RegistrationChallenges
            .Include(c => c.User)
            .FirstOrDefaultAsync(c => c.Method == ConfirmationMethod.MagicLink && c.SecretHash == hash, cancellationToken);
    }

    private async Task<RegistrationError?> SendChallengeAsync(
        User user, RegistrationChallenge challenge, string secret, CancellationToken cancellationToken)
    {
        var message = RegistrationEmails.Create(user.Email, challenge.Method, secret, _options.MagicLinkUrl);
        try
        {
            await emailSender.SendAsync(message, cancellationToken);
        }
        catch (EmailDeliveryException ex)
        {
            logger.ConfirmationEmailFailed(challenge.Id, user.Id, challenge.Method, ex);
            return new RegistrationError(
                RegistrationErrorKind.EmailDeliveryFailed,
                "The confirmation email could not be sent. The registration is saved; request a new email via /auth/register/resend.");
        }

        logger.ConfirmationEmailSent(challenge.Id, user.Id, challenge.Method);
        return null;
    }

    private async Task<bool> TrySaveNewUserAsync(CancellationToken cancellationToken)
    {
        try
        {
            await db.SaveChangesAsync(cancellationToken);
            return true;
        }
        catch (DbUpdateException ex) when (ex.IsUniqueViolation(EmailUniqueIndex))
        {
            return false;
        }
    }

    private async Task<bool> TrySaveConcurrentAsync(CancellationToken cancellationToken)
    {
        try
        {
            await db.SaveChangesAsync(cancellationToken);
            return true;
        }
        catch (DbUpdateConcurrencyException)
        {
            return false;
        }
    }

    private static RegistrationError? ValidateConfirmRequest(ConfirmRegistrationRequest request)
    {
        var errors = new Dictionary<string, string[]>();
        if (request.Token is not null)
        {
            if (request.AttemptId is not null || request.Code is not null)
            {
                errors["token"] = ["Send either attemptId and code, or token — not both."];
            }
            else if (!ChallengeSecrets.IsWellFormedToken(request.Token))
            {
                // A malformed token cannot belong to any attempt: same answer as a wrong one.
                return InvalidConfirmation();
            }
        }
        else
        {
            if (request.AttemptId is null)
            {
                errors["attemptId"] = ["attemptId is required with code."];
            }

            if (request.Code is null)
            {
                errors["code"] = ["Either code (with attemptId) or token is required."];
            }
            else if (!ChallengeSecrets.IsWellFormedCode(request.Code))
            {
                errors["code"] = [$"Code must consist of {ChallengeSecrets.OtpLength} digits."];
            }
        }

        return errors.Count == 0
            ? null
            : new RegistrationError(RegistrationErrorKind.Validation, "Confirmation data is invalid.", errors);
    }

    private RegistrationError EmailTaken()
    {
        logger.RegistrationRejected("email_taken", "email");
        return new RegistrationError(RegistrationErrorKind.EmailTaken, "This email is already registered.");
    }

    private static RegistrationError InvalidConfirmation() => new(
        RegistrationErrorKind.InvalidConfirmation,
        "The confirmation code or link is invalid or expired.");

    private static RegistrationError Contended() => new(
        RegistrationErrorKind.Contended,
        "Too many simultaneous attempts. Try again.",
        RetryAfter: TimeSpan.FromSeconds(1));

    private static RegisteredUserResponse ToResponse(User user) =>
        new(user.Id, user.Email, user.Status == UserStatus.Active ? "active" : "pending");
}
