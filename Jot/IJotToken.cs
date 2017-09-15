/*
 * Jot v1.1
 * License: The MIT License (MIT)
 * Code: https://github.com/jdemeuse1204/Jot
 * Email: james.demeuse@gmail.com
 * Copyright (c) 2016 James Demeuse
 */

namespace Jot
{
    public interface IJotToken
    {
        T GetClaim<T>(string claimKey);

        T GetClaimOrDefault<T>(string claimKey);

        object GetClaim(string claimKey);

        void SetClaim(string claimKey, object value);

        bool ClaimExists(string claimKey);


        T GetHeader<T>(string headerKey);

        T GetHeaderOrDefault<T>(string headerKey);

        object GetHeader(string headerKey);

        void SetHeader(string headerKey, object value);

        bool HeaderExists(string headerKey);

        bool TryGetClaim(string claimKey, out object value);

        bool TryGetHeader(string headerKey, out object value);
    }
}
