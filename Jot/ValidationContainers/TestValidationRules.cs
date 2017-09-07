using Jot.Attributes;
using Jot.Time;

namespace Jot.ValidationContainers
{
    public class TestValidationRules
    {
        private long UnixTimeStamp = new UnixTimeProvider().GetUnixTimestamp();

        [VerifyClaim("nbf")]
        public TokenValidationResult ValidateIatClaim(int claimValue)
        {
            return claimValue <= UnixTimeStamp ? TokenValidationResult.Passed : TokenValidationResult.NotBeforeFailed;
        }

        [VerifyClaim("exp")]
        public TokenValidationResult ValidateExpClaim(int claimValue)
        {
            return UnixTimeStamp < claimValue ? TokenValidationResult.Passed : TokenValidationResult.TokenExpired;
        }

        [VerifyClaim("iat")]
        public TokenValidationResult ValidateIatClaim(string claimValue)
        {
            double value;
            return double.TryParse(claimValue, out value) ? TokenValidationResult.Passed : TokenValidationResult.TokenExpired;
        }
    }
}
