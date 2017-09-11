using Jot.Time;

namespace Jot.Rules
{
    public abstract class RfcBaseRules
    {
        protected long UnixTimeStamp = new UnixTimeProvider().GetUnixTimestamp();

        protected bool IsNbfClaimValid(long claimValue)
        {
            return claimValue <= UnixTimeStamp;
        }

        protected bool IsExpClaimValid(long claimValue)
        {
            return UnixTimeStamp < claimValue;
        }

        protected bool IsIatClaimValid(string claimValue)
        {
            double value;
            return double.TryParse(claimValue, out value);
        }
    }
}
