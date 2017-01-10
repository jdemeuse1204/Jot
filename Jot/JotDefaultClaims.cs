/*
 * Jot v1.0
 * License: The MIT License (MIT)
 * Code: https://github.com/jdemeuse1204/Jot
 * Email: james.demeuse@gmail.com
 * Copyright (c) 2016 James Demeuse
 */

namespace Jot
{
    public static class JotDefaultClaims
    {
        /// <summary>
        /// Issued At
        /// </summary>
        public const string IAT = "iat";

        /// <summary>
        /// Expiration Date
        /// </summary>
        public const string EXP = "exp";

        /// <summary>
        /// Token Id
        /// </summary>
        public const string JTI = "jti"; 

        /// <summary>
        /// Issuer
        /// </summary>
        public const string ISS = "iss"; 

        /// <summary>
        /// Audience
        /// </summary>
        public const string AUD = "aud"; 

        /// <summary>
        /// Not Before
        /// </summary>
        public const string NBF = "nbf";

        /// <summary>
        /// Subject
        /// </summary>
        public const string SUB = "sub"; 
    }
}
