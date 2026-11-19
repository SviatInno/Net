using System.Globalization;
using Microsoft.AspNetCore.Mvc;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure;

/// <summary>Writes RFC 9457 problem details with a machine-readable <c>code</c> outside of endpoints.</summary>
public static class ProblemResponses
{
    public static async Task WriteAsync(
        HttpContext http, int status, string code, string title, string detail, TimeSpan? retryAfter = null)
    {
        http.Response.StatusCode = status;
        if (retryAfter is { } delay)
        {
            http.Response.Headers.RetryAfter = RetryAfterSeconds(delay).ToString(CultureInfo.InvariantCulture);
        }

        var problem = new ProblemDetails { Status = status, Title = title, Detail = detail };
        problem.Extensions["code"] = code;
        await http.RequestServices.GetRequiredService<IProblemDetailsService>().WriteAsync(new ProblemDetailsContext
        {
            HttpContext = http,
            ProblemDetails = problem,
        });
    }

    public static int RetryAfterSeconds(TimeSpan delay) => Math.Max(1, (int)Math.Ceiling(delay.TotalSeconds));
}
