using Jot.Time;
using System;
using System.Collections.Generic;

namespace Jot
{
    //https://stormpath.com/blog/jwt-the-right-way
    //https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1.4
    internal class JwtToken : IJotToken
    {
        #region Properties And Fields

        private readonly Dictionary<string, object> _claims;

        private readonly Dictionary<string, object> _header;

        #endregion

        #region Constructor

        public JwtToken(IUnixTimeProvider timeProvider, int jwtTimeOut)
        {
            _claims = new Dictionary<string, object>
                {
                    {JotDefaultClaims.IAT, timeProvider.GetUnixTimestamp()},
                    {JotDefaultClaims.EXP, timeProvider.GetUnixTimestamp(jwtTimeOut)},
                    {JotDefaultClaims.JTI, Guid.NewGuid()},
                    {JotDefaultClaims.ISS, ""},
                    {JotDefaultClaims.AUD, ""},
                    {JotDefaultClaims.NBF, timeProvider.GetUnixTimestamp()},
                    {JotDefaultClaims.SUB, ""}
                };

            _header = new Dictionary<string, object>
                {
                    {JotDefaultHeaders.ALG, ""},
                    {JotDefaultHeaders.TYP, "JWT"}
                };
        }

        public JwtToken(Dictionary<string, object> header, Dictionary<string, object> claims)
        {
            _claims = claims;
            _header = header;
        }

        #endregion
        public void SetClaim(string claimKey, object value)
        {
            if (!_claims.ContainsKey(claimKey))
            {
                _claims.Add(claimKey, value);
                return;
            }

            _claims[claimKey] = value;
        }

        public bool ClaimExists(string claimKey)
        {
            return _claims.ContainsKey(claimKey);
        }

        public T GetHeader<T>(string headerKey)
        {
            return GetClaimOrHeader<T>(_header, headerKey);
        }

        public T GetHeaderOrDefault<T>(string headerKey)
        {
            return GetClaimOrHeaderOrDefault<T>(_header, headerKey);
        }

        public object GetHeader(string headerKey)
        {
            return _header[headerKey];
        }

        public void SetHeader(string headerKey, object value)
        {
            if (!_header.ContainsKey(headerKey))
            {
                _header.Add(headerKey, value);
                return;
            }

            _header[headerKey] = value;
        }

        public bool HeaderExists(string headerKey)
        {
            return _header.ContainsKey(headerKey);
        }

        public T GetClaim<T>(string claimKey)
        {
            return GetClaimOrHeader<T>(_claims, claimKey);
        }

        public T GetClaimOrDefault<T>(string claimKey)
        {
            return GetClaimOrHeaderOrDefault<T>(_claims, claimKey);
        }

        public object GetClaim(string claimKey)
        {
            return _claims[claimKey];
        }

        public Dictionary<string, object> GetHeaders()
        {
            return _header;
        }

        public Dictionary<string, object> GetClaims()
        {
            return _claims;
        }

        public bool TryGetClaim(string claimKey, out object value)
        {
            value = null;

            if (ClaimExists(claimKey))
            {
                value = _claims[claimKey];
                return true;
            }

            return false;
        }

        public bool TryGetHeader(string headerKey, out object value)
        {
            value = null;

            if (HeaderExists(headerKey))
            {
                value = _header[headerKey];
                return true;
            }

            return false;
        }

        private T GetClaimOrHeaderOrDefault<T>(Dictionary<string, object> values, string key)
        {
            return values[key] == null ? default(T) : GetClaimOrHeader<T>(values, key);

        }

        private T GetClaimOrHeader<T>(Dictionary<string, object> values, string key)
        {
            var value = values[key];
            var isNull = value == null;

            try
            {
                return isNull && (typeof(T).IsNullable() || typeof(T) == typeof(string)) ? null : value.ConvertTo<T>();
            }
            catch (Exception ex)
            {
                if (isNull)
                {
                    // throw more informative error
                    throw new JotException($"Cannot convert null value.  Key: {key}");
                }
                throw ex;
            }

        }
    }
}
