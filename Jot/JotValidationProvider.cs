using Jot.Attributes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;

namespace Jot
{
    internal class JotValidationProvider<T> : JotBaseProvider<T> where T : class
    {
        #region Validation

        /// <summary>
        /// 
        /// </summary>
        /// <param name="encodedToken"></param>
        /// <returns></returns>
        public TokenValidationResult Validate(string encodedToken)
        {
            return Validate(encodedToken, Secret, null);
        }

        public TokenValidationResult Validate(string encodedToken, string secret)
        {
            return Validate(encodedToken, secret, null);
        }

        public TokenValidationResult Validate(string encodedToken, object payload)
        {
            return Validate(encodedToken, Secret, payload);
        }

        public TokenValidationResult Validate(string encodedToken, string secret, object payload)
        {
            var token = Decode(encodedToken);
            var jwt = token as JwtToken;

            if (jwt == null) return TokenValidationResult.TokenNotCorrectlyFormed;

            // if the split does not produce 3 parts the decode part will catch it
            var signatureFromToken = encodedToken.Split('.')[2];

            // re create signature to check for a match
            var recreatedSignedSignature = GetHashedSignature(jwt);

            if (!string.Equals(signatureFromToken, recreatedSignedSignature)) return TokenValidationResult.SignatureNotValid;

            // build the validator
            var claimValidationMethods = typeof(T).GetMethods(BindingFlags.Instance | BindingFlags.Public)
                .Where(w => w.ReturnType == typeof(TokenValidationResult) && w.HasAttribute<VerifyClaim>())
                .ToList();
            var headerValidationMethods = typeof(T).GetMethods(BindingFlags.Instance | BindingFlags.Public)
                .Where(w => w.ReturnType == typeof(TokenValidationResult) && w.HasAttribute<VerifyHeader>())
                .ToList();
            var onFail = typeof(T).GetMethods(BindingFlags.Instance | BindingFlags.Public)
                .FirstOrDefault(w => w.HasAttribute<OnValidationFail>());

            // perform all claim checks
            var claimChecks = ExecuteChecks<VerifyClaim>(claimValidationMethods, onFail, token, payload);

            if (claimChecks != TokenValidationResult.Passed) { return claimChecks; }

            // perform all header checks
            return ExecuteChecks<VerifyHeader>(headerValidationMethods, onFail, token, payload);
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

        private TokenValidationResult ExecuteChecks<K>(List<MethodInfo> checks, MethodInfo onFail, IJotToken token, object payload) where K : IVerifiable
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

                    TryInvokeOnFail(onFail, TokenValidationResult.ClaimMissing, claimOrHeader.Key, null);

                    return claimOrHeader is VerifyClaim ? TokenValidationResult.ClaimMissing : TokenValidationResult.HeaderMissing;
                }

                var claimOrHeaderValue = GetClaimValue(token, claimOrHeader as dynamic);
                var parameters = check.GetParameters().ToList();
                var claimParameter = JotCreationHelper.GetUndecoratedParameters(parameters);
                var additionalParameters = JotCreationHelper.GetInjectableItemAttributes(parameters);

                if (claimParameter.Count != 1)
                {
                    throw new JotException($"Method {check.Name} has more than one parameter.  If there is more than one parameter all additional parameters must be decorated with the InjectAdditionalClaim attribute.  Key: {claimOrHeader.Key}");
                }

                if (additionalParameters.Count == 0 && claimParameter[0].ParameterType == typeof(object))
                {
                    result = (TokenValidationResult)check.Invoke(RuleInstance, new object[] { claimOrHeaderValue });

                    if (result != TokenValidationResult.Passed)
                    {
                        TryInvokeOnFail(onFail, result, claimOrHeader.Key, claimOrHeaderValue);
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

                string missingClaimKey;
                List<object> methodParameters = GetMethodParameters<K>(additionalParameters, token, payload, out missingClaimKey);

                // missing claim class?
                if (!string.IsNullOrEmpty(missingClaimKey))
                {
                    TryInvokeOnFail(onFail, result, missingClaimKey, null);
                    return TokenValidationResult.ClaimMissing;
                }

                var convertedValue = claimOrHeaderValue == null ? null : ConvertClaimValue(parameters[0], claimOrHeader.Key, claimOrHeaderValue, claimOrHeader as dynamic);
                methodParameters.Insert(0, (dynamic)convertedValue);

                result = (TokenValidationResult)check.Invoke(RuleInstance, methodParameters.ToArray());

                if (result != TokenValidationResult.Passed)
                {
                    TryInvokeOnFail(onFail, result, claimOrHeader.Key, claimOrHeaderValue);
                    return result;
                }
            }

            return result;
        }

        private List<object> GetMethodParameters<K>(List<ParameterInfo> parameters, IJotToken token, object payload, out string missingKey) where K : IVerifiable
        {
            missingKey = string.Empty;
            var additionalParameters = parameters.Select(w => new
            {
                Parameter = w,
                Attribute = w.GetCustomAttributes(false).First(x => x.GetType() == typeof(InjectAdditionalClaim) || x.GetType() == typeof(InjectFromPayload))
            }).ToList();
            List<object> methodParameters = new List<object>();

            foreach (var item in additionalParameters)
            {
                if (item.Attribute is InjectAdditionalClaim)
                {
                    bool claimOrHeaderExists;
                    var injectableAdditionalClaimAttribute = (InjectAdditionalClaim)item.Attribute;
                    methodParameters.Add(GetAdditionalParameterValue<K>(item.Parameter, token, injectableAdditionalClaimAttribute, out claimOrHeaderExists));

                    if (!claimOrHeaderExists && string.IsNullOrEmpty(missingKey)) { missingKey = injectableAdditionalClaimAttribute.Key; }
                    continue;
                }

                methodParameters.Add(GetAdditionalParameterValue(item.Parameter, (InjectFromPayload)item.Attribute, payload));
            }

            return methodParameters;
        }

        private dynamic GetAdditionalParameterValue(ParameterInfo parameter, InjectFromPayload attribute, object payload)
        {
            if (payload == null)
            {
                throw new JotException("Payload is null, cannot find properties on a null payload.");
            }

            var property = payload.GetType().GetProperty(attribute.PropertyName);

            if (property == null)
            {
                throw new JotException($"Payload is missing property.  Property Name: {attribute.PropertyName}");
            }

            object value = null;

            try
            {
                value = property.GetValue(payload, null);

                return value.ConvertTo(parameter.GetParameterType());
            }
            catch (Exception)
            {
                throw new JotException($"Cannot convert Payload property {attribute.PropertyName} from {value.GetType().Name} to {parameter.GetParameterType().Name}.  Payload Property Name: {attribute.PropertyName}");
            }
        }

        private dynamic GetAdditionalParameterValue<K>(ParameterInfo parameter, IJotToken token, InjectAdditionalClaim attribute, out bool claimOrHeaderExists) where K : IVerifiable
        {
            claimOrHeaderExists = typeof(K) == typeof(VerifyClaim) ? token.ClaimExists(attribute.Key) : token.HeaderExists(attribute.Key);

            if (!claimOrHeaderExists)
            {
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

        private void TryInvokeOnFail(MethodInfo onFail, TokenValidationResult tokenResult, string claimKey, object claimValue)
        {
            try
            {
                onFail?.Invoke(RuleInstance, new object[] { tokenResult, claimKey, claimValue });
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

        #region Decode
        public IJotToken Decode(string encodedToken)
        {
            var parts = encodedToken.Split('.').ToList();

            if (parts.Count != 3) throw new JotException("Token does not consist of three parts");

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
            var claimsObject = DecodeObject(claimSegment);
            var headerObject = DecodeObject(headerSegment);

            return new JwtToken(headerObject, claimsObject);
        }
        #endregion
    }
}
