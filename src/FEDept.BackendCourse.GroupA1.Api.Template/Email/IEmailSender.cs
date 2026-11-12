namespace FEDept.BackendCourse.GroupA1.Api.Template.Email;

public sealed record EmailMessage(string To, string Subject, string TextBody);

public interface IEmailSender
{
    /// <exception cref="EmailDeliveryException">The SMTP server did not accept the message.</exception>
    Task SendAsync(EmailMessage message, CancellationToken cancellationToken);
}

public sealed class EmailDeliveryException(string message, Exception? inner = null) : Exception(message, inner);
