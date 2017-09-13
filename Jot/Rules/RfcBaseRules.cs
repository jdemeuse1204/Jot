using Jot.Time;

namespace Jot.Rules
{
    public abstract class RfcBaseRules
    {
        protected IUnixTimeProvider UnixTimeProvider = new UnixTimeProvider();

        protected bool IsNbfClaimValid(long claimValue)
        {
            return claimValue <= GetTimeStamp(0);
        }

        protected bool IsExpClaimValid(long claimValue)
        {
            return GetTimeStamp(0) < claimValue;
        }

        protected virtual long GetTimeStamp(int minutesToAdd)
        {
            return UnixTimeProvider.GetUnixTimestamp();
        }

        protected bool IsIatClaimValid(string claimValue)
        {
            double value;
            return double.TryParse(claimValue, out value);
        }
    }
}
