using System.Collections.Concurrent;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Features.Authentication;

/// <summary>
/// At most <see cref="LoginOptions.MaxFailuresPerEmailAndIp"/> failed password checks per
/// (email, IP) pair within a sliding <see cref="LoginOptions.FailureWindow"/>. Checked before the
/// slow hash. In-memory: with several API instances each one counts separately
/// (move it to a shared store such as Redis or PostgreSQL when scaling out).
/// </summary>
public sealed class LoginFailureLimiter(TimeProvider timeProvider)
{
    private const int SweepThreshold = 10_000;

    private readonly ConcurrentDictionary<string, Failures> _failures = new(StringComparer.Ordinal);

    /// <returns>How long to wait, or <c>null</c> when another check is allowed.</returns>
    public TimeSpan? RetryAfter(string key)
    {
        if (!_failures.TryGetValue(key, out var failures))
        {
            return null;
        }

        var now = timeProvider.GetUtcNow();
        lock (failures)
        {
            failures.Prune(now);
            return failures.Times.Count >= LoginOptions.MaxFailuresPerEmailAndIp
                ? failures.Times.Peek() + LoginOptions.FailureWindow - now
                : null;
        }
    }

    public void RecordFailure(string key)
    {
        var now = timeProvider.GetUtcNow();
        var failures = _failures.GetOrAdd(key, _ => new Failures());
        lock (failures)
        {
            failures.Prune(now);
            failures.Times.Enqueue(now);
        }

        if (_failures.Count > SweepThreshold)
        {
            Sweep(now);
        }
    }

    private void Sweep(DateTimeOffset now)
    {
        foreach (var (key, failures) in _failures)
        {
            lock (failures)
            {
                failures.Prune(now);
                if (failures.Times.Count == 0)
                {
                    _failures.TryRemove(new KeyValuePair<string, Failures>(key, failures));
                }
            }
        }
    }

    private sealed class Failures
    {
        public Queue<DateTimeOffset> Times { get; } = new();

        public void Prune(DateTimeOffset now)
        {
            while (Times.Count > 0 && Times.Peek() + LoginOptions.FailureWindow <= now)
            {
                Times.Dequeue();
            }
        }
    }
}
