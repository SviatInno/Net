using System.Data.Common;
using System.Net;
using FEDept.BackendCourse.GroupA1.Api.Template.Data;
using FEDept.BackendCourse.GroupA1.Api.Template.Email;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure;
using FEDept.BackendCourse.GroupA1.Api.Template.Security;
using FEDept.BackendCourse.GroupA1.Api.Template.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Authentication;

/// <summary>
/// Login by email and password, optionally followed by an email challenge (OTP or magic link).
/// Every change of an attempt runs in a transaction that locks the user row first and then the
/// attempt row, so login, confirm and resend of one user are serialized and cannot deadlock.
/// </summary>
public sealed class LoginService(
    AppDbContext db,
    IPasswordHasher passwordHasher,
    DummyPasswordHash dummyPasswordHash,
    LoginSecrets secrets,
    TokenService tokens,
    LoginFailureLimiter failureLimiter,
    AuditIdentifiers audit,
    IEmailSender emailSender,
    TimeProvider timeProvider,
    IOptionsSnapshot<LoginOptions> options,
    ILogger<LoginService> logger)
{
    private const string LoginOperation = "login";
    private const string ConfirmOperation = "confirm";
    private const string ResendOperation = "resend";

    private readonly LoginOptions _options = options.Value;

    public async Task<AuthResult<LoginOutcome>> LoginAsync(
        LoginRequest request, IPAddress? clientIp, CancellationToken cancellationToken)
    {
        var errors = new Dictionary<string, string[]>();
        if (UserEmail.Validate(request.Email) is { } emailError)
        {
            errors["email"] = [emailError];
        }

        // The password is taken as is: no trimming or normalization.
        if (string.IsNullOrEmpty(request.Password))
        {
            errors["password"] = ["Password is required."];
        }

        if (errors.Count > 0)
        {
            logger.LoginFailed("unknown", "validation_failed");
            return new AuthError(AuthErrorKind.Validation, "Login data is invalid.", errors);
        }

        var email = UserEmail.Normalize(request.Email!);
        var emailSubject = audit.ForEmail(email);

        // Before the slow hash, so a blocked pair costs the server nothing.
        var limiterKey = $"{emailSubject}|{clientIp?.ToString() ?? "unknown"}";
        if (failureLimiter.RetryAfter(limiterKey) is { } wait)
        {
            logger.LoginRateLimited(emailSubject, "email_ip");
            return new AuthError(
                AuthErrorKind.RateLimited,
                "Too many failed sign-in attempts. Try again later.",
                RetryAfter: wait);
        }

        var user = await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Email == email, cancellationToken);

        // An unknown email is checked against a dummy hash: same cost as a wrong password.
        var passwordMatches = passwordHasher.Verify(request.Password!, user?.PasswordHash ?? dummyPasswordHash.Value);
        if (user is null || !passwordMatches || user.Status != UserStatus.Active)
        {
            failureLimiter.RecordFailure(limiterKey);
            var reason = user is null ? "unknown_email" : !passwordMatches ? "wrong_password" : "user_inactive";
            logger.LoginFailed(user?.Id.ToString() ?? emailSubject, reason);
            return InvalidCredentials();
        }

        if (!_options.ConfirmationEnabled)
        {
            if (IssueTokens(user.Id) is not { } pair)
            {
                return TokenIssueFailed();
            }

            logger.LoginSucceeded(user.Id, "direct");
            return new LoginOutcome(pair, null);
        }

        return await StartChallengeAsync(user, cancellationToken);
    }

    public async Task<AuthResult<TokenPair>> ConfirmAsync(ConfirmLoginRequest request, CancellationToken cancellationToken)
    {
        var parsed = ParseConfirmRequest(request);
        if (parsed.Error is { } validationError)
        {
            logger.ChallengeRejected(null, parsed.AttemptId, ConfirmOperation, "validation_failed");
            return validationError;
        }

        var (attemptId, method, secret) = (parsed.AttemptId!.Value, parsed.Method, parsed.Secret!);

        // Only to learn which user row to lock first; no decision is made on this read.
        var userId = await FindUserIdAsync(attemptId, cancellationToken);
        if (userId is null)
        {
            return Rejected(null, attemptId, ConfirmOperation, "not_found", InvalidConfirmation());
        }

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var user = await LockUserAsync(userId.Value, cancellationToken);
        var challenge = await LockChallengeAsync(attemptId, cancellationToken);

        if (challenge is null || challenge.Method != method)
        {
            return Rejected(userId, attemptId, ConfirmOperation, "not_found", InvalidConfirmation());
        }

        if (challenge.ConsumedReason is { } consumed)
        {
            return consumed == LoginChallengeConsumedReason.AttemptsExhausted
                ? Rejected(userId, attemptId, ConfirmOperation, "attempts_exhausted", AttemptsExhausted())
                : Rejected(userId, attemptId, ConfirmOperation, LoginChallengeMethods.ReasonName(consumed), InvalidConfirmation());
        }

        var now = timeProvider.GetUtcNow();
        if (now >= challenge.ExpiresAt)
        {
            // An expired attempt does not consume the counter.
            return Rejected(userId, attemptId, ConfirmOperation, "expired", InvalidConfirmation());
        }

        if (user is not { Status: UserStatus.Active })
        {
            challenge.Consume(LoginChallengeConsumedReason.UserInactive, now);
            await db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return Rejected(userId, attemptId, ConfirmOperation, "user_inactive", InvalidCredentials());
        }

        if (!secrets.Matches(challenge.SecretHash, method, secret))
        {
            if (method == LoginChallengeMethod.MagicLink)
            {
                return Rejected(userId, attemptId, ConfirmOperation, "wrong_secret", InvalidConfirmation());
            }

            // The verdict is returned only after the wrong entry is committed.
            challenge.Attempts++;
            var exhausted = challenge.Attempts >= LoginOptions.MaxCodeAttempts;
            if (exhausted)
            {
                challenge.Consume(LoginChallengeConsumedReason.AttemptsExhausted, now);
            }

            await db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return Rejected(userId, attemptId, ConfirmOperation, exhausted ? "wrong_secret_attempts_exhausted" : "wrong_secret", InvalidConfirmation());
        }

        // Both tokens are signed before the attempt is consumed: on failure the transaction
        // rolls back and the same code or link can be confirmed again.
        if (IssueTokens(user.Id) is not { } pair)
        {
            return TokenIssueFailed();
        }

        challenge.Consume(LoginChallengeConsumedReason.Confirmed, now);
        if (await TryCommitAsync(transaction, user.Id, cancellationToken) is { } commitError)
        {
            return commitError;
        }

        logger.ChallengeConfirmed(user.Id, attemptId, LoginChallengeMethods.ToName(method));
        logger.LoginSucceeded(user.Id, LoginChallengeMethods.ToName(method));
        return pair;
    }

    public async Task<AuthResult<LoginResendResponse>> ResendAsync(ResendLoginRequest request, CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(request.AttemptId, out var attemptId))
        {
            logger.ChallengeRejected(null, null, ResendOperation, "validation_failed");
            return new AuthError(
                AuthErrorKind.Validation,
                "Resend data is invalid.",
                new Dictionary<string, string[]> { ["attemptId"] = ["attemptId is required."] });
        }

        var userId = await FindUserIdAsync(attemptId, cancellationToken);
        if (userId is null)
        {
            return Rejected(null, attemptId, ResendOperation, "not_found", InvalidConfirmation());
        }

        string secret;
        LoginChallenge? challenge;
        User? user;
        await using (var transaction = await db.Database.BeginTransactionAsync(cancellationToken))
        {
            user = await LockUserAsync(userId.Value, cancellationToken);
            challenge = await LockChallengeAsync(attemptId, cancellationToken);
            if (challenge is null)
            {
                return Rejected(userId, attemptId, ResendOperation, "not_found", InvalidConfirmation());
            }

            if (challenge.ConsumedReason is { } consumed)
            {
                return consumed == LoginChallengeConsumedReason.AttemptsExhausted
                    ? Rejected(userId, attemptId, ResendOperation, "attempts_exhausted", AttemptsExhausted())
                    : Rejected(userId, attemptId, ResendOperation, LoginChallengeMethods.ReasonName(consumed), InvalidConfirmation());
            }

            var now = timeProvider.GetUtcNow();
            if (user is not { Status: UserStatus.Active })
            {
                challenge.Consume(LoginChallengeConsumedReason.UserInactive, now);
                await db.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return Rejected(userId, attemptId, ResendOperation, "user_inactive", InvalidCredentials());
            }

            // An expired TTL blocks confirmation, not resend.
            if (now < challenge.ResendAllowedAt)
            {
                return Rejected(userId, attemptId, ResendOperation, "too_early", ResendTooEarly(challenge.ResendAllowedAt - now));
            }

            // Same method as the attempt was created with, whatever the configuration says now.
            secret = LoginSecrets.NewSecret(challenge.Method);
            challenge.Reissue(secrets.Hash(challenge.Method, secret), now);
            if (await TryCommitAsync(transaction, user.Id, cancellationToken) is { } commitError)
            {
                return commitError;
            }
        }

        logger.ChallengeResent(user.Id, attemptId, LoginChallengeMethods.ToName(challenge.Method));

        // The new hash stays committed even if SMTP fails: the old secret is not restored.
        if (!await TrySendAsync(user.Email, challenge, secret))
        {
            return new AuthError(
                AuthErrorKind.EmailDeliveryFailed,
                "The sign-in email could not be sent. Request a new one after the cooldown.",
                RetryAfter: LoginOptions.ResendCooldown);
        }

        return LoginResendResponse.From(challenge);
    }

    private async Task<AuthResult<LoginOutcome>> StartChallengeAsync(User user, CancellationToken cancellationToken)
    {
        // Cheap check without locks; repeated under the locks below.
        var openSentAt = await db.LoginChallenges.AsNoTracking()
            .Where(c => c.UserId == user.Id && c.ConsumedAt == null)
            .Select(c => (DateTimeOffset?)c.LastSentAt)
            .FirstOrDefaultAsync(cancellationToken);
        var now = timeProvider.GetUtcNow();
        if (openSentAt is { } sentAt && now < sentAt + LoginOptions.ResendCooldown)
        {
            return Rejected(user.Id, null, LoginOperation, "too_early", ResendTooEarly(sentAt + LoginOptions.ResendCooldown - now));
        }

        var method = _options.ConfirmationMethod;
        var secret = LoginSecrets.NewSecret(method);
        LoginChallenge challenge;
        try
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            var locked = await LockUserAsync(user.Id, cancellationToken);
            if (locked is not { Status: UserStatus.Active })
            {
                logger.LoginFailed(user.Id.ToString(), "user_inactive");
                return InvalidCredentials();
            }

            var previous = await LockOpenChallengeAsync(user.Id, cancellationToken);
            now = timeProvider.GetUtcNow();
            if (previous is not null)
            {
                if (now < previous.ResendAllowedAt)
                {
                    return Rejected(user.Id, previous.Id, LoginOperation, "too_early", ResendTooEarly(previous.ResendAllowedAt - now));
                }

                previous.Consume(LoginChallengeConsumedReason.Replaced, now);

                // Saved before the insert: the partial unique index allows one open attempt per user.
                await db.SaveChangesAsync(cancellationToken);
            }

            challenge = LoginChallenge.Create(Guid.CreateVersion7(now), user.Id, method, secrets.Hash(method, secret), now);
            db.LoginChallenges.Add(challenge);
            await db.SaveChangesAsync(cancellationToken);

            // Committed before SMTP is contacted: an email never points to an attempt that does not exist.
            await transaction.CommitAsync(cancellationToken);
        }
        catch (Exception ex) when (ex is DbException or DbUpdateException)
        {
            logger.ChallengeNotSaved(user.Id, ex.GetType().Name);
            return new AuthError(AuthErrorKind.ServiceUnavailable, "The sign-in attempt could not be saved. Try again.");
        }

        logger.ChallengeCreated(user.Id, challenge.Id, LoginChallengeMethods.ToName(method));

        if (!await TrySendAsync(user.Email, challenge, secret))
        {
            var retryAfter = challenge.ResendAllowedAt - timeProvider.GetUtcNow();
            return new AuthError(
                AuthErrorKind.EmailDeliveryFailed,
                "The sign-in email could not be sent. The attempt is saved: request a new email via /auth/login/resend after the cooldown.",
                RetryAfter: retryAfter,
                Extensions: new Dictionary<string, object?>
                {
                    ["confirmationRequired"] = true,
                    ["method"] = LoginChallengeMethods.ToName(method),
                    ["attemptId"] = challenge.Id,
                    ["retryAfterSeconds"] = ProblemResponses.RetryAfterSeconds(retryAfter),
                });
        }

        return new LoginOutcome(null, LoginPendingResponse.From(challenge));
    }

    private async Task<bool> TrySendAsync(string email, LoginChallenge challenge, string secret)
    {
        var message = LoginEmails.Create(email, challenge, secret, _options.MagicLinkUrl);
        try
        {
            // Not tied to the request: the attempt is already committed, so the email should go out.
            await emailSender.SendAsync(message, CancellationToken.None);
        }
        catch (EmailDeliveryException ex)
        {
            logger.ChallengeEmailFailed(
                challenge.UserId, challenge.Id, LoginChallengeMethods.ToName(challenge.Method), (ex.InnerException ?? ex).GetType().Name);
            return false;
        }

        logger.ChallengeEmailSent(challenge.UserId, challenge.Id, LoginChallengeMethods.ToName(challenge.Method));
        return true;
    }

    private TokenPair? IssueTokens(Guid userId)
    {
        try
        {
            return tokens.IssuePair(userId);
        }
        catch (TokenIssueException ex)
        {
            logger.TokenIssueFailed(userId, (ex.InnerException ?? ex).GetType().Name);
            return null;
        }
    }

    private async Task<AuthError?> TryCommitAsync(
        Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction, Guid userId, CancellationToken cancellationToken)
    {
        try
        {
            await db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return null;
        }
        catch (Exception ex) when (ex is DbException or DbUpdateException)
        {
            logger.ChallengeNotSaved(userId, ex.GetType().Name);
            return new AuthError(AuthErrorKind.ServiceUnavailable, "The sign-in attempt could not be saved. Try again.");
        }
    }

    private Task<Guid?> FindUserIdAsync(Guid attemptId, CancellationToken cancellationToken) =>
        db.LoginChallenges.AsNoTracking()
            .Where(c => c.Id == attemptId)
            .Select(c => (Guid?)c.UserId)
            .FirstOrDefaultAsync(cancellationToken);

    // Lock order everywhere: users row, then login_challenges row.
    private async Task<User?> LockUserAsync(Guid userId, CancellationToken cancellationToken) =>
        (await db.Users
            .FromSql($"SELECT * FROM users WHERE id = {userId} FOR UPDATE")
            .ToListAsync(cancellationToken))
        .SingleOrDefault();

    private async Task<LoginChallenge?> LockChallengeAsync(Guid attemptId, CancellationToken cancellationToken) =>
        (await db.LoginChallenges
            .FromSql($"SELECT * FROM login_challenges WHERE id = {attemptId} FOR UPDATE")
            .ToListAsync(cancellationToken))
        .SingleOrDefault();

    private async Task<LoginChallenge?> LockOpenChallengeAsync(Guid userId, CancellationToken cancellationToken) =>
        (await db.LoginChallenges
            .FromSql($"SELECT * FROM login_challenges WHERE user_id = {userId} AND consumed_at IS NULL FOR UPDATE")
            .ToListAsync(cancellationToken))
        .SingleOrDefault();

    private AuthError Rejected(Guid? userId, Guid? attemptId, string operation, string reason, AuthError error)
    {
        logger.ChallengeRejected(userId, attemptId, operation, reason);
        return error;
    }

    private static ConfirmRequestParts ParseConfirmRequest(ConfirmLoginRequest request)
    {
        if (request.Token is not null)
        {
            if (request.AttemptId is not null || request.Code is not null)
            {
                return ConfirmRequestParts.Invalid(new AuthError(
                    AuthErrorKind.Validation,
                    "Confirmation data is invalid.",
                    new Dictionary<string, string[]> { ["token"] = ["Send either attemptId and code, or token — not both."] }));
            }

            // A malformed token cannot belong to any attempt: same answer as a wrong one.
            return LoginSecrets.TryParseToken(request.Token, out var tokenAttemptId, out var tokenSecret)
                ? new ConfirmRequestParts(null, tokenAttemptId, LoginChallengeMethod.MagicLink, tokenSecret)
                : ConfirmRequestParts.Invalid(InvalidConfirmation());
        }

        var errors = new Dictionary<string, string[]>();
        Guid attemptId = default;
        if (string.IsNullOrWhiteSpace(request.AttemptId) || !Guid.TryParse(request.AttemptId, out attemptId))
        {
            errors["attemptId"] = ["attemptId is required with code."];
        }

        if (request.Code is null)
        {
            errors["code"] = ["Either code (with attemptId) or token is required."];
        }
        else if (!LoginSecrets.IsWellFormedCode(request.Code))
        {
            errors["code"] = [$"Code must consist of exactly {LoginSecrets.OtpLength} digits."];
        }

        return errors.Count > 0
            ? ConfirmRequestParts.Invalid(new AuthError(AuthErrorKind.Validation, "Confirmation data is invalid.", errors))
            : new ConfirmRequestParts(null, attemptId, LoginChallengeMethod.Otp, request.Code);
    }

    private static AuthError InvalidCredentials() => new(
        AuthErrorKind.InvalidCredentials,
        "The email or password is incorrect.");

    private static AuthError InvalidConfirmation() => new(
        AuthErrorKind.InvalidConfirmation,
        "The sign-in code or link is invalid or expired.");

    private static AuthError AttemptsExhausted() => new(
        AuthErrorKind.AttemptsExhausted,
        "Too many wrong codes. Sign in again to get a new code.");

    private static AuthError ResendTooEarly(TimeSpan retryAfter) => new(
        AuthErrorKind.ResendTooEarly,
        "A sign-in email was sent recently. Try again later.",
        RetryAfter: retryAfter,
        Extensions: new Dictionary<string, object?> { ["retryAfterSeconds"] = ProblemResponses.RetryAfterSeconds(retryAfter) });

    private static AuthError TokenIssueFailed() => new(
        AuthErrorKind.TokenIssueFailed,
        "Sign-in could not be completed. Try again.");

    private sealed record ConfirmRequestParts(AuthError? Error, Guid? AttemptId, LoginChallengeMethod Method, string? Secret)
    {
        public static ConfirmRequestParts Invalid(AuthError error) => new(error, null, default, null);
    }
}
