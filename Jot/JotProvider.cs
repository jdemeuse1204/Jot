using Jot.Rules.Creation;
using Jot.Rules.Verification;
using System.Collections.Generic;

namespace Jot
{
    public static class JotProvider
    {
        #region Validation
        public static TokenValidationResult Validate(string encodedToken)
        {
            return Validate<JotDefaultValidationRules>(encodedToken);
        }

        public static TokenValidationResult Validate(string encodedToken, string secret)
        {
            return Validate<JotDefaultValidationRules>(encodedToken, secret);
        }

        public static TokenValidationResult Validate(string encodedToken, string secret, object payload)
        {
            return Validate<JotDefaultValidationRules>(encodedToken, secret, payload);
        }

        public static TokenValidationResult Validate<T>(string encodedToken) where T : class
        {
            return new JotValidationProvider<T>().Validate(encodedToken);
        }

        public static TokenValidationResult Validate<T>(string encodedToken, string secret) where T : class
        {
            return new JotValidationProvider<T>().Validate(encodedToken, secret);
        }

        public static TokenValidationResult Validate<T>(string encodedToken, string secret, object payload) where T : class
        {
            return new JotValidationProvider<T>().Validate(encodedToken, secret, payload);
        }
        #endregion

        #region Creation
        public static IJotToken Create()
        {
            return Create<JotDefaultCreationRules>();
        }

        public static IJotToken Create(Dictionary<string, object> claims)
        {
            return Create<JotDefaultCreationRules>(claims);
        }

        public static IJotToken Create(Dictionary<string, object> claims, Dictionary<string, object> extraHeaders)
        {
            return Create<JotDefaultCreationRules>(claims, extraHeaders);
        }

        public static IJotToken Create<T>() where T : class
        {
            return new JotCreationProvider<T>().Create();
        }

        public static IJotToken Create<T>(Dictionary<string, object> claims) where T : class
        {
            return new JotCreationProvider<T>().Create(claims);
        }

        public static IJotToken Create<T>(Dictionary<string, object> claims, Dictionary<string, object> extraHeaders) where T : class
        {
            return new JotCreationProvider<T>().Create(claims, extraHeaders);
        }
        #endregion

        #region Encode
        public static string Encode(IJotToken token)
        {
            return new JotCreationProvider<JotDefaultCreationRules>().Encode(token);
        }

        public static string Encode<T>(IJotToken token) where T : class
        {
            return new JotCreationProvider<T>().Encode(token);
        }

        public static string Encode(IJotToken token, string secret)
        {
            return new JotCreationProvider<JotDefaultCreationRules>().Encode(token, secret);
        }

        public static string Encode<T>(IJotToken token, string secret) where T : class
        {
            return new JotCreationProvider<T>().Encode(token, secret);
        }
        #endregion

        #region Decode
        public static IJotToken Decode(string encodedToken)
        {
            return new JotValidationProvider<JotDefaultValidationRules>().Decode(encodedToken);
        }

        public static IJotToken Decode<T>(string encodedToken) where T : class
        {
            return new JotValidationProvider<T>().Decode(encodedToken);
        }
        #endregion
    }
}
