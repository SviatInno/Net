using FEDept.BackendCourse.GroupA1.Api.Template.Data;
using FEDept.BackendCourse.GroupA1.Api.Template.Users;
using Microsoft.EntityFrameworkCore;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Authentication;

/// <summary>
/// Stateless sessions: nothing about a token is stored. Every token is accepted only while
/// its user exists and is <c>active</c>; a used refresh token stays valid until its own exp.
/// </summary>
public sealed class SessionService(
    AppDbContext db,
    TokenService tokens,
    ILogger<SessionService> logger)
{
    public async Task<AuthResult<TokenPair>> RefreshAsync(string? refreshToken, CancellationToken cancellationToken)
    {
        var validation = await tokens.ValidateAsync(refreshToken, TokenUse.Refresh);
        if (validation.UserId is not { } userId)
        {
            logger.RefreshRejected(null, validation.FailureCategory!);
            return InvalidSession();
        }

        // A database outage throws here and becomes 503, never 401.
        if (!await IsActiveAsync(userId, cancellationToken))
        {
            logger.RefreshRejected(userId, "user_inactive");
            return InvalidSession();
        }

        TokenPair pair;
        try
        {
            pair = tokens.IssuePair(userId);
        }
        catch (TokenIssueException ex)
        {
            logger.TokenIssueFailed(userId, (ex.InnerException ?? ex).GetType().Name);
            return new AuthError(AuthErrorKind.TokenIssueFailed, "The session could not be refreshed. Try again.");
        }

        logger.RefreshSucceeded(userId);
        return pair;
    }

    /// <summary>Reads only the user's status; roles are never taken from the token.</summary>
    public Task<bool> IsActiveAsync(Guid userId, CancellationToken cancellationToken) =>
        db.Users.AsNoTracking().AnyAsync(u => u.Id == userId && u.Status == UserStatus.Active, cancellationToken);

    private static AuthError InvalidSession() => new(
        AuthErrorKind.InvalidSession,
        "The session is invalid or has expired. Sign in again.");
}
