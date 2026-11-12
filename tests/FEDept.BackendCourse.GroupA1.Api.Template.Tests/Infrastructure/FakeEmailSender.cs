using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using FEDept.BackendCourse.GroupA1.Api.Template.Email;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Infrastructure;

public sealed partial class FakeEmailSender : IEmailSender
{
    private readonly ConcurrentQueue<EmailMessage> _sent = new();

    /// <summary>When set, every send fails like an SMTP server refusing the message.</summary>
    public bool Fail { get; set; }

    public IReadOnlyCollection<EmailMessage> Sent => _sent;

    public Task SendAsync(EmailMessage message, CancellationToken cancellationToken)
    {
        if (Fail)
        {
            throw new EmailDeliveryException("SMTP refused (test).");
        }

        _sent.Enqueue(message);
        return Task.CompletedTask;
    }

    public EmailMessage LastTo(string email) => _sent.Last(m => m.To == email);

    public string LastCodeFor(string email) => CodePattern().Match(LastTo(email).TextBody).Groups[1].Value;

    public string LastTokenFor(string email) =>
        Uri.UnescapeDataString(TokenPattern().Match(LastTo(email).TextBody).Groups[1].Value);

    [GeneratedRegex(@"code: (\d{6})")]
    private static partial Regex CodePattern();

    [GeneratedRegex(@"[?&]token=([^\s&]+)")]
    private static partial Regex TokenPattern();
}
