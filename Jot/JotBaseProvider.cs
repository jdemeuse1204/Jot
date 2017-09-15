using Jot.Time;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace Jot
{
    internal class JotBaseProvider<T> where T : class
    {
        #region Properties and Fields
        protected readonly T RuleInstance;
        private readonly MethodInfo _onHashMethod;
        private readonly MethodInfo _onSerialize;
        private readonly MethodInfo _onDeserialize;
        private readonly MethodInfo _onGetGhostClaims;
        private readonly string _secret;
        private readonly HashAlgorithm? _hashAlgorithm;
        private readonly IUnixTimeProvider _timeProvider;

        protected readonly IDictionary<HashAlgorithm, Func<string, byte[], byte[]>> HashAlgorithms = new Dictionary<HashAlgorithm, Func<string, byte[], byte[]>>
        {
            {
                HashAlgorithm.HS256, (key, value) =>
                {
                    using (var sha = new HMACSHA256(Encoding.UTF8.GetBytes(key)))
                    {
                        return sha.ComputeHash(value);
                    }
                }
            },
            {
                HashAlgorithm.HS384, (key, value) =>
                {
                    using (var sha = new HMACSHA384(Encoding.UTF8.GetBytes(key)))
                    {
                        return sha.ComputeHash(value);
                    }
                }
            },
            {
                HashAlgorithm.HS512, (key, value) =>
                {
                    using (var sha = new HMACSHA512(Encoding.UTF8.GetBytes(key)))
                    {
                        return sha.ComputeHash(value);
                    }
                }
            }
        };
        #endregion

        #region Constructor
        public JotBaseProvider()
        {
            RuleInstance = Activator.CreateInstance<T>();
            _onHashMethod = JotCreationHelper.GetOnHashMethod<T>();
            _onSerialize = JotCreationHelper.GetOnSerializeMethod<T>();
            _onDeserialize = JotCreationHelper.GetOnDeserializeMethod<T>();
            _onGetGhostClaims = JotCreationHelper.GetOnGetGhostClaims<T>();
            _hashAlgorithm = JotCreationHelper.GetHashAlgorithm<T>();
            _secret = JotCreationHelper.GetSecret<T>(RuleInstance);

            if (_onHashMethod == null && _hashAlgorithm == null)
            {
                throw new JotException($"Cannot find HashAlgorithm, please either decorate {typeof(T).Name} with the HashAlgorithmType attribute or add a method to {typeof(T).Name} and decorate that method with OnHash");
            }

            _timeProvider = JotCreationHelper.GetOnGetUnixTimeProvider<T>(RuleInstance);
        }
        #endregion  

        #region Object Serialization
        protected Dictionary<string, object> DecodeObject(string jsonString)
        {
            return _onDeserialize != null ? _onDeserialize.Invoke<Dictionary<string, object>>(RuleInstance, new object[] { jsonString }) : Serializer.ToObject<Dictionary<string, object>>(jsonString);
        }

        protected string SerializeObject(object entity)
        {
            return _onSerialize != null ? _onSerialize.Invoke<string>(RuleInstance, new object[] { entity }) : Serializer.ToJSON(entity);
        }
        #endregion

        #region Hash
        protected string Hash(byte[] messageBytes)
        {
            byte[] hashed;
            var onHashMethod = JotCreationHelper.GetOnHashMethod<T>();

            if (onHashMethod != null)
            {
                hashed = onHashMethod.InvokeAndMatchParameters<byte[]>(RuleInstance, new object[] { messageBytes, _secret });
            }
            else
            {
                hashed = HashAlgorithms[_hashAlgorithm.Value](_secret, messageBytes);
            }

            return UrlEncode.Base64UrlEncode(hashed);
        }

        protected string GetHashedSignature(JwtToken jwt)
        {
            // get the headers
            var jwtHeaders = jwt.GetHeaders();
            var jwtClaims = jwt.GetClaims(); // do not include ghost claims

            // serialize header and claims
            var header = SerializeObject(jwtHeaders);
            var claims = SerializeObject(jwtClaims);
            var signatureClaims = _onGetGhostClaims != null ? SerializeObject(GetClaimsWithGhostClaims(jwt)) : claims;

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
            return Hash(signatureBytes);
        }
        #endregion

        #region Other
        protected Dictionary<string, object> GetClaimsWithGhostClaims(JwtToken jwt)
        {
            var onGetGhostClaims = JotCreationHelper.GetOnGetGhostClaims<T>();

            var ghostClaims = onGetGhostClaims.Invoke<Dictionary<string, object>>(RuleInstance, null);

            if (ghostClaims == null || ghostClaims.Count == 0) throw new JotException("Ghost claims cannot be null or blank.");

            var jwtClaims = jwt.GetClaims();

            var result = jwtClaims.ToDictionary(claim => claim.Key, claim => claim.Value);

            foreach (var ghostClaim in ghostClaims) result.Add(ghostClaim.Key, ghostClaim.Value);

            return result;
        }

        #endregion

        #region Decode

        public IJotToken Decode(string encodedToken)
        {
            var parts = encodedToken.Split('.');

            if (parts.Count() != 3) throw new JotException("Token does not consist of three parts");

            // create rules
            var rules = Activator.CreateInstance<T>();

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
