/*
 * Jot v1.1
 * License: The MIT License (MIT)
 * Code: https://github.com/jdemeuse1204/Jot
 * Email: james.demeuse@gmail.com
 * Copyright (c) 2016 James Demeuse
 */

using System;

namespace Jot.Time
{
    public class UnixTimeProvider : IUnixTimeProvider
    {
        private static readonly long EpochTicks = new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero).Ticks;
        private readonly ITimeProvider _timeProvider;

        internal UnixTimeProvider(ITimeProvider timeProvider)
        {
            _timeProvider = timeProvider;
        }

        public UnixTimeProvider() : this(new TimeProvider())
        {
        }

        /// <summary>
        ///     Gets the unix timestamp (time since epoch) based on Universal Time.
        /// </summary>
        public long GetUnixTimestamp()
        {
            return GetUnixTimestamp(0);
        }

        /// <summary>
        ///     Gets the unix timestamp (time since epoch) based on Universal Time.
        /// </summary>
        /// <param name="minutesToAdd">The minutes to add to current UTC time.</param>
        public long GetUnixTimestamp(int minutesToAdd)
        {
            var utcNow = _timeProvider.UtcNow.AddMinutes(minutesToAdd);

            return (utcNow.Ticks - EpochTicks) / TimeSpan.TicksPerSecond;
        }
    }
}