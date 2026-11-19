using System.Globalization;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Authentication;

public enum TokenUse
{
    Access,
    Refresh,
}

/// <summary>Both tokens of a pair are signed before any cookie is written.</summary>
public sealed record TokenPair(string AccessToken, string RefreshToken);

/// <summary>Either a verified user id or a log category (never shown to the client).</summary>
public readonly record struct TokenValidation(Guid? UserId, string? FailureCategory)
{
    public static TokenValidation Valid(Guid userId) => new(userId, null);

    public static TokenValidation Invalid(string category) => new(null, category);
}

public sealed class TokenIssueException(Exception inner) : Exception("Token signing failed.", inner);

/// <summary>
/// HS256 JWTs: access (JWT_ACCESS_SECRET, 15 min) and refresh (JWT_REFRESH_SECRET, 30 days).
/// Payload is exactly <c>sub, iss, aud, iat, exp, token_use</c>: no jti, roles or personal data.
/// Nothing is stored on the server. Lifetime is checked here against <see cref="TimeProvider"/>.
/// </summary>
public sealed class TokenService
{
    public const string TokenUseClaim = "token_use";

    private readonly JsonWebTokenHandler _handler = new() { SetDefaultTimesOnTokenCreation = false };
    private readonly AuthKeysOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly SymmetricSecurityKey _accessKey;
    private readonly SymmetricSecurityKey _refreshKey;

    public TokenService(IOptions<AuthKeysOptions> options, TimeProvider timeProvider)
    {
        _options = options.Value;
        _timeProvider = timeProvider;
        _accessKey = new SymmetricSecurityKey(_options.JwtAccessSecret);
        _refreshKey = new SymmetricSecurityKey(_options.JwtRefreshSecret);
    }

    /// <exception cref="TokenIssueException">Signing failed; no token of the pair may be used.</exception>
    public TokenPair IssuePair(Guid userId)
    {
        var now = _timeProvider.GetUtcNow();
        try
        {
            return new TokenPair(
                Create(userId, TokenUse.Access, now, LoginOptions.AccessTokenLifetime),
                Create(userId, TokenUse.Refresh, now, LoginOptions.RefreshTokenLifetime));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new TokenIssueException(ex);
        }
    }

    public async Task<TokenValidation> ValidateAsync(string? token, TokenUse use)
    {
        if (string.IsNullOrEmpty(token))
        {
            return TokenValidation.Invalid("missing");
        }

        var result = await _handler.ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
            IssuerSigningKey = use == TokenUse.Access ? _accessKey : _refreshKey,
            RequireSignedTokens = true,
            ValidIssuer = _options.JwtIssuer,
            ValidAudience = _options.JwtAudience,
            ValidateIssuer = true,
            ValidateAudience = true,
            // exp / iat are checked below with the injected clock and a 30-second skew.
            ValidateLifetime = false,
            RequireExpirationTime = false,
        });

        if (!result.IsValid)
        {
            return TokenValidation.Invalid(result.Exception switch
            {
                SecurityTokenInvalidSignatureException
                    or SecurityTokenSignatureKeyNotFoundException
                    or SecurityTokenInvalidAlgorithmException => "signature",
                SecurityTokenInvalidIssuerException or SecurityTokenInvalidAudienceException => "claims",
                _ => "malformed",
            });
        }

        var jwt = (JsonWebToken)result.SecurityToken;
        if (!jwt.TryGetPayloadValue<long>(JwtRegisteredClaimNames.Iat, out var iat)
            || !jwt.TryGetPayloadValue<long>(JwtRegisteredClaimNames.Exp, out var exp)
            || exp <= iat
            || !Guid.TryParseExact(jwt.Subject, "D", out var userId)
            || userId == Guid.Empty)
        {
            return TokenValidation.Invalid("claims");
        }

        var now = _timeProvider.GetUtcNow();
        if (DateTimeOffset.FromUnixTimeSeconds(iat) > now + LoginOptions.ClockSkew)
        {
            return TokenValidation.Invalid("claims");
        }

        if (DateTimeOffset.FromUnixTimeSeconds(exp) + LoginOptions.ClockSkew <= now)
        {
            return TokenValidation.Invalid("expired");
        }

        if (!jwt.TryGetPayloadValue<string>(TokenUseClaim, out var tokenUse) || tokenUse != UseName(use))
        {
            return TokenValidation.Invalid("token_use");
        }

        return TokenValidation.Valid(userId);
    }

    private string Create(Guid userId, TokenUse use, DateTimeOffset now, TimeSpan lifetime) =>
        _handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _options.JwtIssuer,
            Audience = _options.JwtAudience,
            IssuedAt = now.UtcDateTime,
            Expires = (now + lifetime).UtcDateTime,
            Claims = new Dictionary<string, object>
            {
                [JwtRegisteredClaimNames.Sub] = userId.ToString("D", CultureInfo.InvariantCulture),
                [TokenUseClaim] = UseName(use),
            },
            SigningCredentials = new SigningCredentials(
                use == TokenUse.Access ? _accessKey : _refreshKey,
                SecurityAlgorithms.HmacSha256),
        });

    private static string UseName(TokenUse use) => use == TokenUse.Access ? "access" : "refresh";
}
