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
    public class JotDefaultValidationRules : RfcBaseRules
    {
        [Required]
        [VerifyClaim("nbf")]
        public TokenValidationResult ValidateNbfClaim(long claimValue)
        {
            return IsIatClaimValid(claimValue) ? TokenValidationResult.Passed : TokenValidationResult.NotBeforeFailed;
        }

        [Required]
        [VerifyClaim("exp")]
        public TokenValidationResult ValidateExpClaim(int claimValue)
        {
            return IsExpClaimValid(claimValue) ? TokenValidationResult.Passed : TokenValidationResult.TokenExpired;
        }

        [Required]
        [VerifyClaim("iat")]
        public TokenValidationResult ValidateIatClaim(string claimValue)
        {
            return IsIatClaimValid(claimValue) ? TokenValidationResult.Passed : TokenValidationResult.CreatedTimeCheckFailed;
        }
    }
}
