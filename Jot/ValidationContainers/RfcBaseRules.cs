using Jot.Time;

namespace Jot.ValidationContainers
{
    public abstract class RfcBaseRules
    {
        protected long UnixTimeStamp = new UnixTimeProvider().GetUnixTimestamp();

        public bool IsIatClaimValid(long claimValue)
        {
            return claimValue <= UnixTimeStamp;
        }

        public bool IsExpClaimValid(long claimValue)
        {
            return UnixTimeStamp < claimValue;
        }

        public bool IsIatClaimValid(string claimValue)
        {
            double value;
            return double.TryParse(claimValue, out value);
        }
    }
}
