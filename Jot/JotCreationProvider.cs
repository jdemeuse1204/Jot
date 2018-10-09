using Jot.Rules.Verification;
using System;
using System.Collections.Generic;
using System.Text;

namespace Jot
{
    internal class JotCreationProvider<T> : JotBaseProvider<T> where T : class
    {
        #region Refresh Token

        /// <summary>
        /// 
        /// </summary>
        /// <param name="encodedToken"></param>
        /// <returns></returns>
        public IJotToken Refresh(string encodedToken)
        {
            var token = new JotValidationProvider<JotDefaultValidationRules>().Decode(encodedToken);

            return Refresh(token);
        }

        public IJotToken Refresh<K>(string encodedToken) where K : class
        {
            var token = new JotValidationProvider<K>().Decode(encodedToken);

            return Refresh(token);
        }

        public IJotToken Refresh(IJotToken token)
        {
            var jwt = token as JwtToken;

            if (jwt == null) throw new Exception("Token is not formed correctly");

            var unixTimeProvider = JotCreationHelper.GetOnGetUnixTimeProvider<T>(Activator.CreateInstance<T>());
            var timeout = JotCreationHelper.GetJwtTimeout<T>();

            // refresh the expiration date
            jwt.SetClaim(JotDefaultClaims.EXP, unixTimeProvider.GetUnixTimestamp(timeout));

            return token;
        }

        #endregion

        #region Create
        public IJotToken Create(Dictionary<string, object> claims, Dictionary<string, object> extraHeaders)
        {
            var timeProvider = JotCreationHelper.GetOnGetUnixTimeProvider<T>(RuleInstance);
            var timeout = JotCreationHelper.GetJwtTimeout<T>();
            var token = new JwtToken(timeProvider, timeout);

            // set and add claims
            foreach (var claim in claims) token.SetClaim(claim.Key, claim.Value);

            // add extra headers
            foreach (var header in extraHeaders) token.SetHeader(header.Key, header.Value);

            JotCreationHelper.GetOnCreateMethod<T>().TryInvoke(RuleInstance, new object[] { token });

            return token;
        }

        public IJotToken Create()
        {
            return Create(new Dictionary<string, object>(), new Dictionary<string, object>());
        }

        public IJotToken Create(Dictionary<string, object> claims)
        {
            return Create(claims, new Dictionary<string, object>());
        }
        #endregion

        #region Encode
        public string Encode(IJotToken token)
        {
            var jwt = token as JwtToken;

            if (jwt == null) throw new Exception("Token is not formed correctly");

            var rules = Activator.CreateInstance<T>();
            var secret = JotCreationHelper.GetSecret<T>(rules);

            return Encode(token, secret, rules);
        }

        public string Encode(IJotToken token, string secret)
        {
            var jwt = token as JwtToken;

            if (jwt == null) throw new Exception("Token is not formed correctly");

            var rules = Activator.CreateInstance<T>();

            return Encode(token, secret, rules);
        }

        private string Encode(IJotToken token, string secret, object creationRules)
        {
            var jwt = token as JwtToken;

            if (jwt == null) throw new Exception("Token is not formed correctly");

            // creation data
            var useGhostClaims = JotCreationHelper.IsUsingGhostClaims<T>();
            var hashAlgorithm = JotCreationHelper.GetHashAlgorithm<T>();

            // set algorithm in header of jwt
            jwt.SetHeader(JotDefaultHeaders.ALG, GetEncryptionType(hashAlgorithm));

            // get the headers
            var jwtHeaders = jwt.GetHeaders();
            var jwtClaims = jwt.GetClaims(); // do not include ghost claims

            // serialize header and claims
            var header = SerializeObject(jwtHeaders);
            var claims = SerializeObject(jwtClaims);

            // header and claim bytes
            var headerBytes = Encoding.UTF8.GetBytes(header);
            var claimBytes = Encoding.UTF8.GetBytes(claims);

            //  encoded segments
            var headerSegment = UrlEncode.Base64UrlEncode(headerBytes);
            var claimSegment = UrlEncode.Base64UrlEncode(claimBytes);

            // sign the token
            var getSignedSignature = GetHashedSignature(jwt);

            // return final result
            return string.Concat(headerSegment, ".", claimSegment, ".", getSignedSignature);
        }

        private string GetEncryptionType(HashAlgorithm? hashAlgorithm)
        {
            if (JotCreationHelper.UseAnonymousHeader<T>()) return "Anonymous";

            var onHashMethod = JotCreationHelper.UseAnonymousHeader<T>();

            if (JotCreationHelper.HasOnHashMethod<T>()) return "Custom";

            if (hashAlgorithm == null)
            {
                throw new JotException($"Cannot find HashAlgorithm, please either decorate {typeof(T).Name} with the HashAlgorithmType attribute or add a method to {typeof(T).Name} and decorate that method with OnHash");
            }

            return hashAlgorithm.Value.ToString();
        }
        #endregion
    }
}
