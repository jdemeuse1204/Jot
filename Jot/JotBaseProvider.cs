using Jot.Time;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace Jot
{
    internal abstract class JotBaseProvider<T> where T : class
    {
        #region Properties and Fields
        protected readonly T RuleInstance;
        protected readonly MethodInfo OnHashMethod;
        protected readonly MethodInfo OnSerialize;
        protected readonly MethodInfo OnDeserialize;
        protected readonly MethodInfo OnGetGhostClaims;
        protected readonly string Secret;
        protected readonly HashAlgorithm? HashAlgorithm;
        protected readonly IUnixTimeProvider TimeProvider;

        protected readonly IDictionary<HashAlgorithm, Func<string, byte[], byte[]>> HashAlgorithms = new Dictionary<HashAlgorithm, Func<string, byte[], byte[]>>
        {
            {
                Jot.HashAlgorithm.HS256, (key, value) =>
                {
                    using (var sha = new HMACSHA256(Encoding.UTF8.GetBytes(key)))
                    {
                        return sha.ComputeHash(value);
                    }
                }
            },
            {
                Jot.HashAlgorithm.HS384, (key, value) =>
                {
                    using (var sha = new HMACSHA384(Encoding.UTF8.GetBytes(key)))
                    {
                        return sha.ComputeHash(value);
                    }
                }
            },
            {
                Jot.HashAlgorithm.HS512, (key, value) =>
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
            OnHashMethod = JotCreationHelper.GetOnHashMethod<T>();
            OnSerialize = JotCreationHelper.GetOnSerializeMethod<T>();
            OnDeserialize = JotCreationHelper.GetOnDeserializeMethod<T>();
            OnGetGhostClaims = JotCreationHelper.GetOnGetGhostClaims<T>();
            HashAlgorithm = JotCreationHelper.GetHashAlgorithm<T>();
            Secret = JotCreationHelper.GetSecret<T>(RuleInstance);

            if (OnHashMethod == null && HashAlgorithm == null)
            {
                throw new JotException($"Cannot find HashAlgorithm, please either decorate {typeof(T).Name} with the HashAlgorithmType attribute or add a method to {typeof(T).Name} and decorate that method with OnHash");
            }

            TimeProvider = JotCreationHelper.GetOnGetUnixTimeProvider<T>(RuleInstance);
        }
        #endregion  

        #region Object Serialization
        protected Dictionary<string, object> DecodeObject(string jsonString)
        {
            return OnDeserialize != null ? OnDeserialize.Invoke<Dictionary<string, object>>(RuleInstance, new object[] { jsonString }) : Serializer.ToObject<Dictionary<string, object>>(jsonString);
        }

        protected string SerializeObject(object entity)
        {
            return OnSerialize != null ? OnSerialize.Invoke<string>(RuleInstance, new object[] { entity }) : Serializer.ToJSON(entity);
        }
        #endregion

        #region Hash
        protected string Hash(byte[] messageBytes)
        {
            byte[] hashed;
            var onHashMethod = JotCreationHelper.GetOnHashMethod<T>();

            if (onHashMethod != null)
            {
                hashed = onHashMethod.InvokeAndMatchParameters<byte[]>(RuleInstance, new object[] { messageBytes, Secret });
            }
            else
            {
                hashed = HashAlgorithms[HashAlgorithm.Value](Secret, messageBytes);
            }

            return UrlEncode.Base64UrlEncode(hashed);
        }

        protected string GetHashedSignature(IJotToken jwt)
        {
            // get the headers
            var jwtHeaders = jwt.GetHeaders();
            var jwtClaims = jwt.GetClaims(); // do not include ghost claims

            // serialize header and claims
            var header = SerializeObject(jwtHeaders);
            var claims = SerializeObject(jwtClaims);
            var signatureClaims = OnGetGhostClaims != null ? SerializeObject(GetClaimsWithGhostClaims(jwt)) : claims;

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
        protected Dictionary<string, object> GetClaimsWithGhostClaims(IJotToken jwt)
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
    }
}
