using System;

namespace Jot.Tests.Common
{
    public static class UnixDateServices
    {
        public static double GetUnixTimestamp(double jwtAuthorizationTimeOut)
        {
            var millisecondsTimeOut = ((jwtAuthorizationTimeOut * 60) * 1000);

            return Math.Round(GetUnixTimestamp() + millisecondsTimeOut);
        }

        private static DateTime _unixEpoch()
        {
            return new DateTime(1970, 1, 1).ToLocalTime();
        }

        public static double GetUnixTimestamp()
        {
            return Math.Round(DateTime.UtcNow.Subtract(_unixEpoch()).TotalSeconds);
        }
    }

}
