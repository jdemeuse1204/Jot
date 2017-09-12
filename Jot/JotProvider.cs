/*
 * Jot v1.1
 * License: The MIT License (MIT)
 * Code: https://github.com/jdemeuse1204/Jot
 * Email: james.demeuse@gmail.com
 * Copyright (c) 2016 James Demeuse
 */

using Jot.Attributes;
using Jot.Time;
using Jot.Rules;
using System;
using System.Collections.Generic;
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
            return Validate<JotDefaultRules>(encodedToken);
        }

        public TokenValidationResult Validate(string encodedToken, string secret)
        {
            return Validate<JotDefaultRules>(encodedToken, secret);
        }

        public TokenValidationResult Validate<T>(string encodedToken) where T : class
        {
            var section = _getConfigurationSection();

            return Validate<T>(encodedToken, section.GetEncryptionSecret());
        }

        public TokenValidationResult Validate<T>(string encodedToken, string secret) where T : class
        {
            return Validate(encodedToken, secret, Activator.CreateInstance<T>());
        }

        public TokenValidationResult Validate<T>(string encodedToken, T validationRules) where T : class
        {
            var section = _getConfigurationSection();

            return Validate(encodedToken, section.GetEncryptionSecret(), validationRules);
        }

        public TokenValidationResult Validate<T>(string encodedToken, string secret, T validationRules) where T : class
        {
            var token = Decode(encodedToken);
            var jwt = token as JwtToken;
            var alreadyValidatedClaims = new List<string>();

            if (jwt == null) return TokenValidationResult.TokenNotCorrectlyFormed;

            // if the split does not produce 3 parts the decode part will catch it
            var signatureFromToken = encodedToken.Split('.')[2];

            // re create signature to check for a match
            var recreatedSignedSignature = _getEncrytedSignature(jwt, secret);

            if (!string.Equals(signatureFromToken, recreatedSignedSignature)) return TokenValidationResult.SignatureNotValid;

            // build the validator
            var claimValidationMethods = typeof(T).GetMethods(BindingFlags.Instance | BindingFlags.Public)
                .Where(w => w.ReturnType == typeof(TokenValidationResult) && w.GetCustomAttributes(false).Any(x => x.GetType() == typeof(VerifyClaim)))
                .ToList();
            var headerValidationMethods = typeof(T).GetMethods(BindingFlags.Instance | BindingFlags.Public)
                .Where(w => w.ReturnType == typeof(TokenValidationResult) && w.GetCustomAttributes(false).Any(x => x.GetType() == typeof(VerifyHeader)))
                .ToList();
            var onFail = typeof(T).GetMethods(BindingFlags.Instance | BindingFlags.Public)
                .FirstOrDefault(w => w.GetCustomAttributes(false).Any(x => x.GetType() == typeof(OnValidationFail)));

            // perform all claim checks
            var claimChecks = ExecuteChecks<T, VerifyClaim>(claimValidationMethods, onFail, token, validationRules);

            if (claimChecks != TokenValidationResult.Passed) { return claimChecks; }

            // perform all header checks
            return ExecuteChecks<T, VerifyHeader>(headerValidationMethods, onFail, token, validationRules);
        }

        private bool ClaimExists(IJotToken token, VerifyClaim claimAttribute)
        {
            return token.ClaimExists(claimAttribute.Key);
        }

        private bool ClaimExists(IJotToken token, VerifyHeader headerAttribute)
        {
            return token.HeaderExists(headerAttribute.Key);
        }

        private object GetClaimValue(IJotToken token, VerifyClaim claimAttribute)
        {
            return token.GetClaim(claimAttribute.Key);
        }

        private object GetClaimValue(IJotToken token, VerifyHeader headerAttribute)
        {
            return token.GetHeader(headerAttribute.Key);
        }

        private TokenValidationResult ExecuteChecks<T, K>(List<MethodInfo> checks, MethodInfo onFail, IJotToken token, T validator) where T : class where K : IVerifiable
        {
            var result = TokenValidationResult.Passed;

            foreach (var check in checks)
            {
                var attributes = check.GetCustomAttributes(false);
                var claimOrHeader = (IVerifiable)attributes.FirstOrDefault(w => w.GetType() == typeof(K));
                var required = (Required)attributes.FirstOrDefault(w => w.GetType() == typeof(Required));

                if (check.ReturnType != typeof(TokenValidationResult))
                {
                    throw new JotException($"Method {check.Name} must have return type of TokenValidationResult. Key: {claimOrHeader.Key}");
                }

                // if the token is missing, do not verify
                if (!ClaimExists(token, claimOrHeader as dynamic))
                {
                    if (required == null) { continue; }

                    TryInvokeOnFail(validator, onFail, TokenValidationResult.ClaimMissing, claimOrHeader.Key, null);

                    return claimOrHeader is VerifyClaim ? TokenValidationResult.ClaimMissing : TokenValidationResult.HeaderMissing;
                }

                var claimOrHeaderValue = GetClaimValue(token, claimOrHeader as dynamic);
                var parameters = check.GetParameters().ToList();
                var claimParameter = parameters.Where(w => w.GetCustomAttributes(false).All(x => x.GetType() != typeof(InjectAdditionalClaim))).ToList();
                var additionalParameters = parameters.Where(w => w.GetCustomAttributes(false).Any(x => x.GetType() == typeof(InjectAdditionalClaim))).ToList();

                if (claimParameter.Count != 1)
                {
                    throw new JotException($"Method {check.Name} has more than one parameter.  If there is more than one parameter all additional parameters must be decorated with the InjectAdditionalClaim attribute.  Key: {claimOrHeader.Key}");
                }

                if (additionalParameters.Count == 0 && claimParameter[0].ParameterType == typeof(object))
                {
                    result = (TokenValidationResult)check.Invoke(validator, new object[] { claimOrHeaderValue });

                    if (result != TokenValidationResult.Passed)
                    {
                        TryInvokeOnFail(validator, onFail, result, claimOrHeader.Key, claimOrHeaderValue);
                        return result;
                    }
                }

                var isNullable = parameters[0].ParameterType.IsNullable();

                if (claimOrHeaderValue == null)
                {
                    if (!isNullable && parameters[0].ParameterType != typeof(string))
                    {
                        throw new JotException($"Method {check.Name} must have nullable parameter because claim value is null. Key: {claimOrHeader.Key}");
                    }
                }

                List<object> methodParameters = additionalParameters.Select(w => GetAdditionalParameterValue<K>(w, token)).ToList();

                var convertedValue = claimOrHeaderValue == null ? null : ConvertClaimValue(parameters[0], claimOrHeader.Key, claimOrHeaderValue, claimOrHeader as dynamic);
                methodParameters.Insert(0, (dynamic)convertedValue);

                result = (TokenValidationResult)check.Invoke(validator, methodParameters.ToArray());

                if (result != TokenValidationResult.Passed)
                {
                    TryInvokeOnFail(validator, onFail, result, claimOrHeader.Key, claimOrHeaderValue);
                    return result;
                }
            }

            return result;
        }

        private dynamic GetAdditionalParameterValue<K>(ParameterInfo parameter, IJotToken token) where K : IVerifiable
        {
            var attribute = (InjectAdditionalClaim)parameter.GetCustomAttributes(false).First(w => w.GetType() == typeof(InjectAdditionalClaim));
            var claimOrHeaderExists = typeof(K) == typeof(VerifyClaim) ? token.ClaimExists(attribute.Key) : token.HeaderExists(attribute.Key);

            if (!claimOrHeaderExists)
            {
                if (attribute.IsRequired)
                {
                    throw new JotException($"InjectAdditionalClaim error. Required claim key is missing from token.  Claim Key: {attribute.Key}");
                }

                return null;
            }

            var claimOrHeaderValue = typeof(K) == typeof(VerifyClaim) ? token.GetClaim(attribute.Key) : token.GetHeader(attribute.Key);

            if (claimOrHeaderValue == null) return null;

            return (dynamic)ConvertClaimValue(parameter, attribute.Key, claimOrHeaderValue, attribute);
        }

        private object ConvertClaimValue(ParameterInfo parameter, string claimKey, object value, VerifyClaim attribute)
        {
            try
            {
                return value.ConvertTo(parameter.ParameterType);
            }
            catch (Exception)
            {
                throw new JotException($"Cannot convert Claim {value.GetType().Name} to {parameter.GetParameterType().Name}.  Claim Key: {claimKey}");
            }
        }

        private object ConvertClaimValue(ParameterInfo parameter, string claimKey, object value, VerifyHeader attribute)
        {
            try
            {
                return value.ConvertTo(parameter.ParameterType);
            }
            catch (Exception)
            {
                throw new JotException($"Cannot convert Header Claim {value.GetType().Name} to {parameter.GetParameterType().Name}.  Header Claim Key: {claimKey}");
            }
        }

        private object ConvertClaimValue(ParameterInfo parameter, string claimKey, object value, InjectAdditionalClaim attribute)
        {
            try
            {
                return value.ConvertTo(parameter.ParameterType);
            }
            catch (Exception)
            {
                throw new JotException($"Cannot convert Additional Injected Claim {value.GetType().Name} to {parameter.GetParameterType().Name}.  Additional Injected Claim Key: {claimKey}");
            }
        }

        private void TryInvokeOnFail<T>(T validator, MethodInfo onFail, TokenValidationResult tokenResult, string claimKey, object claimValue) where T : class
        {
            try
            {
                onFail?.Invoke(validator, new object[] { tokenResult, claimKey, claimValue });
            }
            catch (TargetParameterCountException)
            {
                throw new JotException("Parameter mismatch count for OnFail method, must have 3 (TokenValidationResult, String, Object)");
            }
            catch (ArgumentException ex)
            {
                throw new JotException($"Parameter type mismatch for OnFail method.  {ex.Message}");
            }
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
                return GetClaimOrHeader<T>(_header, headerKey);
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
