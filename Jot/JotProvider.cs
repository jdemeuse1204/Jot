﻿/*
 * Jot v1.1
 * License: The MIT License (MIT)
 * Code: https://github.com/jdemeuse1204/Jot
 * Email: james.demeuse@gmail.com
 * Copyright (c) 2016 James Demeuse
 */

using Jot.Attributes;
using Jot.Time;
using Jot.ValidationContainers;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace Jot
{
    public class JotProvider
    {
        #region Constructor
        public JotProvider(int jwtTimeOutInMinutes, HashAlgorithm hashAlgorithm, bool useGhostClaims = false)
        {
            JwtTimeout = jwtTimeOutInMinutes;
            HashAlgorithm = hashAlgorithm;
            UseGhostClaims = useGhostClaims;
            _timeProvider = CreateUnixTimeProvider();
        }

        public JotProvider(IUnixTimeProvider timeProvider, int jwtTimeOutInMinutes, HashAlgorithm hashAlgorithm, bool useGhostClaims = false)
        {
            JwtTimeout = jwtTimeOutInMinutes;
            HashAlgorithm = hashAlgorithm;
            UseGhostClaims = useGhostClaims;
            _timeProvider = timeProvider;
        }

        public JotProvider() : this(CreateUnixTimeProvider())
        {
        }

        private static UnixTimeProvider CreateUnixTimeProvider()
        {
            return new UnixTimeProvider(new TimeProvider());
        }

        public JotProvider(IUnixTimeProvider timeProvider)
        {
            var section = _getConfigurationSection();

            _timeProvider = timeProvider;

            // make sure the configuration is valid
            _checkConfigurationIsValid(section);

            JwtTimeout = section.GetTimeOut();
            HashAlgorithm = section.GetHashAlgorithm();
            UseGhostClaims = section.UseGhostClaims();
        }
        #endregion

        #region Events
        public delegate Dictionary<string, object> OnGetGhostClaimsHandler();

        public event OnGetGhostClaimsHandler OnGetGhostClaims;


        public delegate void OnTokenCreateHandler(IJotToken token);

        public event OnTokenCreateHandler OnCreate;



        public event OnSerializeHandler OnSerialize;

        public delegate string OnSerializeHandler(object toSerialize);



        public event OnDeserializeClaimsHandler OnDeserialize;

        public delegate Dictionary<string, object> OnDeserializeClaimsHandler(string jsonString);



        public event OnHashHandler OnHash;

        public delegate byte[] OnHashHandler(byte[] toEncrypt, string secret);
        #endregion

        #region Properties and Fields
        private readonly IUnixTimeProvider _timeProvider;

        public readonly int JwtTimeout;

        public readonly HashAlgorithm HashAlgorithm;

        public readonly bool UseGhostClaims;

        private readonly IDictionary<HashAlgorithm, Func<string, byte[], string>> _hashAlgorithms = new Dictionary<HashAlgorithm, Func<string, byte[], string>>
        {
            {
                HashAlgorithm.HS256, (key, value) =>
                {
                    using (var sha = new HMACSHA256(Encoding.UTF8.GetBytes(key)))
                    {
                        return UrlEncode.Base64UrlEncode(sha.ComputeHash(value));
                    }
                }
            },
            {
                HashAlgorithm.HS384, (key, value) =>
                {
                    using (var sha = new HMACSHA384(Encoding.UTF8.GetBytes(key)))
                    {
                        return UrlEncode.Base64UrlEncode(sha.ComputeHash(value));
                    }
                }
            },
            {
                HashAlgorithm.HS512, (key, value) =>
                {
                    using (var sha = new HMACSHA512(Encoding.UTF8.GetBytes(key)))
                    {
                        return UrlEncode.Base64UrlEncode(sha.ComputeHash(value));
                    }
                }
            }
        };
        #endregion

        #region Create
        public IJotToken Create(Dictionary<string, object> extraHeaders, Dictionary<string, object> claims)
        {
            var token = new JwtToken(_timeProvider, JwtTimeout);

            // set and add claims
            foreach (var claim in claims) token.SetClaim(claim.Key, claim.Value);

            // add extra headers
            foreach (var header in extraHeaders) token.SetHeader(header.Key, header.Value);

            OnCreate?.Invoke(token);

            return token;
        }

        public IJotToken Create(Dictionary<string, object> claims)
        {
            var token = new JwtToken(_timeProvider, JwtTimeout);

            // set and add claims
            foreach (var claim in claims) token.SetClaim(claim.Key, claim.Value);

            OnCreate?.Invoke(token);

            return token;
        }

        public IJotToken Create()
        {
            var token = new JwtToken(_timeProvider, JwtTimeout);

            OnCreate?.Invoke(token);

            return token;
        }

        #endregion

        #region Configuration
        private void _checkConfigurationIsValid(JotAuthConfigurationSection section)
        {
            if (section == null) throw new JotException("Please configure Jot on the configuration file if you use the parameterless constructor.");

            section.CheckConfigurationIsValid();
        }

        private JotAuthConfigurationSection _getConfigurationSection()
        {
            return System.Configuration.ConfigurationManager.GetSection(JotAuthConfigurationSection.SectionName) as JotAuthConfigurationSection;
        }
        #endregion

        #region Encode
        public string Encode(IJotToken token)
        {
            var jwt = token as JwtToken;

            if (jwt == null) throw new Exception("Token is not formed correctly");

            var section = _getConfigurationSection();

            return Encode(token, section.GetEncryptionSecret());
        }

        public string Encode(IJotToken token, string secret)
        {
            var jwt = token as JwtToken;

            if (jwt == null) throw new Exception("Token is not formed correctly");

            // set algorithm in header of jwt
            jwt.SetHeader(JotDefaultHeaders.ALG, _getEncryptionType());

            // get the headers
            var jwtHeaders = jwt.GetHeaders();
            var jwtClaims = jwt.GetClaims(); // do not include ghost claims

            // serialize header and claims
            var header = _serializeObject(jwtHeaders);
            var claims = _serializeObject(jwtClaims);

            // header and claim bytes
            var headerBytes = Encoding.UTF8.GetBytes(header);
            var claimBytes = Encoding.UTF8.GetBytes(claims);

            //  encoded segments
            var headerSegment = UrlEncode.Base64UrlEncode(headerBytes);
            var claimSegment = UrlEncode.Base64UrlEncode(claimBytes);

            // sign the token
            var getSignedSignature = _getEncrytedSignature(jwt, secret);

            // return final result
            return string.Concat(headerSegment, ".", claimSegment, ".", getSignedSignature);
        }

        private string _getEncryptionType()
        {
            var section = _getConfigurationSection();

            if (section == null) return HashAlgorithm.ToString();

            if (section.AnonymousAlgorithmInHeader()) return "Anonymous";

            if (OnHash != null) return "Custom";

            return HashAlgorithm.ToString();
        }

        #endregion

        #region Other
        private Dictionary<string, object> _getClaimsWithGhostClaims(JwtToken jwt)
        {
            if (OnGetGhostClaims == null) throw new JotException("Ghost claims are being used, but OnGetGhostClaims is null.");

            var ghostClaims = OnGetGhostClaims();

            if (ghostClaims == null || ghostClaims.Count == 0) throw new JotException("Ghost claims cannot be null or blank.");

            var jwtClaims = jwt.GetClaims();

            var result = jwtClaims.ToDictionary(claim => claim.Key, claim => claim.Value);

            foreach (var ghostClaim in ghostClaims) result.Add(ghostClaim.Key, ghostClaim.Value);

            return result;
        }

        private string _getEncrytedSignature(JwtToken jwt, string secret)
        {
            // get the headers
            var jwtHeaders = jwt.GetHeaders();
            var jwtClaims = jwt.GetClaims(); // do not include ghost claims

            // serialize header and claims
            var header = _serializeObject(jwtHeaders);
            var claims = _serializeObject(jwtClaims);
            var signatureClaims = UseGhostClaims ? _serializeObject(_getClaimsWithGhostClaims(jwt)) : claims;

            // header and claim bytes
            var headerBytes = Encoding.UTF8.GetBytes(header);
            var signatureClaimBytes = Encoding.UTF8.GetBytes(signatureClaims);

            //  encoded segments
            var headerSegment = UrlEncode.Base64UrlEncode(headerBytes);
            var signatureClaimsSegment = UrlEncode.Base64UrlEncode(signatureClaimBytes);

            // sign the token
            var unsignedSignature = string.Concat(headerSegment, ".", signatureClaimsSegment);
            var signatureBytes = Encoding.UTF8.GetBytes(unsignedSignature);

            // return encoded signature that must be signed
            return _hash(secret, signatureBytes);
        }

        private string _hash(string secret, byte[] messageBytes)
        {
            return OnHash != null ? UrlEncode.Base64UrlEncode(OnHash(messageBytes, secret)) : _hashAlgorithms[HashAlgorithm](secret, messageBytes);
        }

        #endregion

        #region Decode

        public IJotToken Decode(string encodedToken)
        {
            var parts = encodedToken.Split('.');

            if (parts.Count() != 3) throw new JotException("Token does not consist of three parts");

            // parts
            var header = parts[0];
            var claims = parts[1];

            // get bytes of parts
            var headerBytes = UrlEncode.Base64UrlDecode(header);
            var claimBytes = UrlEncode.Base64UrlDecode(claims);

            // get segments
            var headerSegment = Encoding.UTF8.GetString(headerBytes);
            var claimSegment = Encoding.UTF8.GetString(claimBytes);

            // decode claims to object
            var claimsObject = _decodeObject(claimSegment);
            var headerObject = _decodeObject(headerSegment);

            return new JwtToken(headerObject, claimsObject);
        }
        #endregion

        #region Object Serialization
        public Dictionary<string, object> _decodeObject(string jsonString)
        {
            return OnDeserialize != null ? OnDeserialize(jsonString) : Serializer.ToObject<Dictionary<string, object>>(jsonString);
        }

        private string _serializeObject(object entity)
        {
            return OnSerialize != null ? OnSerialize(entity) : Serializer.ToJSON(entity);
        }
        #endregion

        #region Refresh Token

        /// <summary>
        /// 
        /// </summary>
        /// <param name="encodedToken"></param>
        /// <returns></returns>
        public IJotToken Refresh(string encodedToken)
        {
            var token = Decode(encodedToken);

            return Refresh(token);
        }

        public IJotToken Refresh(IJotToken token)
        {
            var jwt = token as JwtToken;

            if (jwt == null) throw new Exception("Token is not formed correctly");

            // refresh the expiration date
            jwt.SetClaim(JotDefaultClaims.EXP, _timeProvider.GetUnixTimestamp(JwtTimeout));

            return token;
        }

        #endregion

        #region Validation

        /// <summary>
        /// 
        /// </summary>
        /// <param name="encodedToken"></param>
        /// <returns></returns>
        public TokenValidationResult Validate(string encodedToken)
        {
            return Validate<JotDefaultValidationRules>(encodedToken);
        }

        public TokenValidationResult Validate(string encodedToken, string secret)
        {
            return Validate<JotDefaultValidationRules>(encodedToken, secret);
        }

        public TokenValidationResult Validate<T>(string encodedToken) where T : class
        {
            var section = _getConfigurationSection();

            return Validate<T>(encodedToken, section.GetEncryptionSecret());
        }

        public TokenValidationResult Validate<T>(string encodedToken, string secret) where T : class
        {
            var token = Decode(encodedToken);
            var jwt = token as JwtToken;
            var alreadyValidatedClaims = new List<string>();
            var validator = Activator.CreateInstance<T>();

            if (jwt == null) return TokenValidationResult.TokenNotCorrectlyFormed;

            // if the split does not produce 3 parts the decode part will catch it
            var signatureFromToken = encodedToken.Split('.')[2];

            // re create signature to check for a match
            var recreatedSignedSignature = _getEncrytedSignature(jwt, secret);

            if (!string.Equals(signatureFromToken, recreatedSignedSignature)) return TokenValidationResult.SignatureNotValid;

            // build the validator
            var methods = typeof(T).GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly)
                .Where(w => w.ReturnType == typeof(TokenValidationResult) && w.GetCustomAttributesData().Any(x => x.GetType() == typeof(VerifyClaim)))
                .ToList();

            var requiredChecks = methods.Where(w => w.GetCustomAttributesData().Any(x => x.GetType() == typeof(Required))).ToList();
            var optionalChecks = methods.Where(w => w.GetCustomAttributesData().All(x => x.GetType() != typeof(Required))).ToList();

            // perform all required checks
            var requiredChecksResult = ExecuteChecks(requiredChecks, token, validator, false);

            if (requiredChecksResult != TokenValidationResult.Passed) { return requiredChecksResult; }

            // perform all optional checks
            return ExecuteChecks(optionalChecks, token, validator, true);
        }

        private TokenValidationResult ExecuteChecks<T>(List<MethodInfo> checks, IJotToken token, T validator, bool areOptionalClaims) where T : class
        {
            var result = TokenValidationResult.Passed;

            foreach (var check in checks)
            {
                var claim = (VerifyClaim)check.GetCustomAttributes(false).FirstOrDefault(w => w.GetType() == typeof(VerifyClaim));

                if (check.ReturnType != typeof(TokenValidationResult))
                {
                    throw new JotException($"Method {check.Name} must have return type of TokenValidationResult");
                }

                if (claim == null)
                {
                    throw new JotException($"Method {check.Name} is missing Claim attribute from validator {nameof(T)}");
                }

                // if the token is missing, do not verify
                if (!token.ClaimExists(claim.ClaimKey))
                {
                    if (areOptionalClaims) { continue; }

                    return TokenValidationResult.ClaimMissing;
                }

                var claimValue = token.GetClaim(claim.ClaimKey);
                var parameters = check.GetParameters().ToList();

                if (parameters.Count != 1)
                {
                    throw new JotException($"Method {check.Name} must have only one parameter that accepts claim value");
                }

                if (parameters[0].ParameterType == typeof(object))
                {
                    result = (TokenValidationResult)check.Invoke(validator, new object[] { claimValue });

                    if (result != TokenValidationResult.Passed) { return result; }
                }

                if (claimValue == null)
                {
                    if (!IsNullable(parameters[0].ParameterType))
                    {
                        throw new JotException($"Method {check.Name} must have nullable parameter because claim value is null");
                    }
                }

                TypeConverter converter = TypeDescriptor.GetConverter(parameters[0].ParameterType);
                var convertedValue = converter.ConvertFrom(claimValue.ToString());

                result = (TokenValidationResult)check.Invoke(validator, new object[] { (dynamic)convertedValue });

                if (result != TokenValidationResult.Passed) { return result; }
            }

            return result;
        }

        private bool IsNullable(Type type)
        {
            return type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Nullable<>);
        }
        #endregion

        #region Serialization

        private static class Serializer
        {
            public static string ToJSON(object toSerialize)
            {
                return new JavaScriptSerializer().Serialize(toSerialize);
            }

            public static T ToObject<T>(string json) where T : class
            {
                return new JavaScriptSerializer().Deserialize(json, typeof(T)) as T;
            }
        }


        #endregion

        #region Token

        //https://stormpath.com/blog/jwt-the-right-way
        //https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1.4
        private class JwtToken : IJotToken
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
                return typeof(T) == typeof(Guid) ? (T)(dynamic)Guid.Parse(_header[headerKey].ToString()) : (T)Convert.ChangeType(_header[headerKey], typeof(T));
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
                var claimValue = _claims[claimKey];
                var claimValueAsString = claimValue == null ? "" : claimValue.ToString();

                if (typeof(T) == typeof(string) && string.Equals(claimValue, "")) return (T)Convert.ChangeType("", typeof(T));

                if (string.IsNullOrEmpty(claimValueAsString) || string.IsNullOrWhiteSpace(claimValueAsString))
                {
                    return default(T);
                }

                return typeof(T) == typeof(Guid) ? (T)(dynamic)Guid.Parse(_claims[claimKey].ToString()) : (T)Convert.ChangeType(_claims[claimKey], typeof(T));
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
        }

        #endregion

        #region Encoding

        private static class UrlEncode
        {
            // From https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-08#appendix-C
            public static string Base64UrlEncode(byte[] payload)
            {
                var s = Convert.ToBase64String(payload); // Regular base64 encoder
                s = s.Split('=')[0]; // Remove any trailing '='s
                s = s.Replace('+', '-'); // 62nd char of encoding
                s = s.Replace('/', '_'); // 63rd char of encoding
                return s;
            }

            public static byte[] Base64UrlDecode(string payload)
            {
                var s = payload;
                s = s.Replace('-', '+'); // 62nd char of encoding
                s = s.Replace('_', '/'); // 63rd char of encoding
                switch (s.Length % 4) // Pad with trailing '='s
                {
                    case 0:
                        break; // No pad chars in this case
                    case 2:
                        s += "==";
                        break; // Two pad chars
                    case 3:
                        s += "=";
                        break; // One pad char
                    default:
                        throw new Exception("Illegal base64url string!");
                }

                return Convert.FromBase64String(s); // Standard base64 decoder
            }
        }

        #endregion
    }
}
