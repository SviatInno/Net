using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure;
using Microsoft.Extensions.Options;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Security;

/// <summary>
/// Cookie authentication makes every unsafe request a CSRF target. A request whose <c>Origin</c>
/// differs from the API's own origin is accepted only from the exact trusted frontend origin
/// and only with <c>X-CSRF-Protection: 1</c> (a custom header forces a CORS preflight).
/// Requests without <c>Origin</c> (non-browser clients) and same-origin requests pass.
/// </summary>
public sealed partial class CsrfProtectionMiddleware(
    RequestDelegate next,
    IOptions<FrontendOptions> frontend,
    ILogger<CsrfProtectionMiddleware> logger)
{
    public const string HeaderName = "X-CSRF-Protection";

    private readonly FrontendOptions _frontend = frontend.Value;

    public async Task InvokeAsync(HttpContext context)
    {
        var request = context.Request;
        if (HttpMethods.IsGet(request.Method) || HttpMethods.IsHead(request.Method)
            || HttpMethods.IsOptions(request.Method) || HttpMethods.IsTrace(request.Method))
        {
            await next(context);
            return;
        }

        var origin = request.Headers.Origin.ToString();
        if (origin.Length == 0 || IsSameOrigin(request, origin))
        {
            await next(context);
            return;
        }

        if (_frontend.Origin is null || !string.Equals(origin, _frontend.Origin, StringComparison.Ordinal))
        {
            Rejected(logger, "untrusted_origin");
            await RejectAsync(context);
            return;
        }

        if (request.Headers[HeaderName] != "1")
        {
            Rejected(logger, "missing_header");
            await RejectAsync(context);
            return;
        }

        await next(context);
    }

    private static bool IsSameOrigin(HttpRequest request, string origin) =>
        string.Equals(origin, $"{request.Scheme}://{request.Host.Value}", StringComparison.OrdinalIgnoreCase);

    private static Task RejectAsync(HttpContext context) => ProblemResponses.WriteAsync(
        context,
        StatusCodes.Status403Forbidden,
        "csrf_rejected",
        "Forbidden",
        "The request origin is not trusted or the CSRF protection header is missing.");

    // The Origin value itself is not logged (spec 1.5: no full URLs or headers).
    [LoggerMessage(EventId = 920, Level = LogLevel.Warning, Message = "CSRF check rejected a request: {Reason}")]
    private static partial void Rejected(ILogger logger, string reason);
}
