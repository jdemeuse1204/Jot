using Jot.Rules.Creation;
using System;
using System.Collections.Generic;
using System.Text;

namespace Jot
{

    // Creation > Validation > Base

    // creation rules
    // refresh x
    // encode x
    // create

    // validation rules
    // validate
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
            var token = Decode(encodedToken);

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

        #region Encode
        public string Encode(IJotToken token)
        {
            var jwt = token as JwtToken;

            if (jwt == null) throw new Exception("Token is not formed correctly");

            return Encode(token, Activator.CreateInstance<T>());
        }

        private string Encode(IJotToken token, object creationRules)
        {
            var jwt = token as JwtToken;

            if (jwt == null) throw new Exception("Token is not formed correctly");

            // creation data
            var secret = JotCreationHelper.GetSecret<T>(creationRules);
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


        public IJotToken Create(Dictionary<string, object> claims)
        {
            return Create(claims, new Dictionary<string, object>());
        }
        #endregion
    }
}
