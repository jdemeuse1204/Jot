using System;

namespace Jot
{
    public class TimeProvider : ITimeProvider
    {
        private static readonly long EpochTicks = new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero).Ticks;

        public long GetUnixTimestamp()
        {
            return GetUnixTimestamp(0);
        }

        public long GetUnixTimestamp(int minutesToAdd)
        {
            var utcNow = DateTime.UtcNow.AddMinutes(minutesToAdd);

            return (utcNow.Ticks - EpochTicks) / TimeSpan.TicksPerSecond;
        }
    }
}