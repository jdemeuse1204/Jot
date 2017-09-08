/*
 * Jot v1.1
 * License: The MIT License (MIT)
 * Code: https://github.com/jdemeuse1204/Jot
 * Email: james.demeuse@gmail.com
 * Copyright (c) 2016 James Demeuse
 */

using Jot.Attributes;

namespace Jot.ValidationContainers
{
    public class RfcSpecValidationRules : RfcBaseRules
    {
        [VerifyClaim("nbf")]
        public TokenValidationResult ValidateNbfClaim(long? claimValue)
        {
            return claimValue.HasValue && IsIatClaimValid(claimValue.Value) ? TokenValidationResult.Passed : TokenValidationResult.NotBeforeFailed;
        }

        [VerifyClaim("exp")]
        public TokenValidationResult ValidateExpClaim(long? claimValue)
        {
            return claimValue.HasValue && IsExpClaimValid(claimValue.Value) ? TokenValidationResult.Passed : TokenValidationResult.TokenExpired;
        }

        [VerifyClaim("iat")]
        public TokenValidationResult ValidateIatClaim(string claimValue)
        {
            return IsIatClaimValid(claimValue) ? TokenValidationResult.Passed : TokenValidationResult.CreatedTimeCheckFailed;
        }
    }
}
