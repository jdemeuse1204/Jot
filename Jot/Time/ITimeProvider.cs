using System;

namespace Jot.Time
{
    public interface ITimeProvider
    {
        DateTime UtcNow { get; }
    }
}