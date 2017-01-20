/*
 * Jot v1.1
 * License: The MIT License (MIT)
 * Code: https://github.com/jdemeuse1204/Jot
 * Email: james.demeuse@gmail.com
 * Copyright (c) 2016 James Demeuse
 */

namespace Jot
{
    public enum TokenValidationResult
    {
        NotBeforeFailed,
        TokenExpired,
        TokenNotCorrectlyFormed,
        SignatureNotValid,
        OnTokenValidateFailed,
        OnJtiValidateFailed,
        CustomCheckFailed,
        CreatedTimeCheckFailed,
        Passed
    }
}
