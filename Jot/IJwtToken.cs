/*
 * Jot v1.0
 * License: The MIT License (MIT)
 * Code: https://github.com/jdemeuse1204/Jot
 * Email: james.demeuse@gmail.com
 * Copyright (c) 2016 James Demeuse
 */

namespace Jot
{
    public interface IJwtToken
    {
        T GetClaim<T>(string claimKey);

        object GetClaim(string claimKey);

        void SetClaim(string claimKey, object value);

        T GetHeader<T>(string headerKey);

        object GetHeader(string headerKey);

        void SetHeader(string headerKey, object value);
    }
}
