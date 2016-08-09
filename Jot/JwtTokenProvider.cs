/*
 * Jot v1.0
 * License: The MIT License (MIT)
 * Code: https://github.com/jdemeuse1204/Jot
 * Email: james.demeuse@gmail.com
 * Copyright (c) 2016 James Demeuse
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace Jot
{
    public class JwtTokenProvider
    {
        #region Constructor
        public JwtTokenProvider(int jwtTimeOutInMinutes, JwtEncryption encryptionType, bool shouldEncryptHeader)
        {
            JwtTimeout = jwtTimeOutInMinutes;
            EncryptionType = encryptionType;
            ShouldEncryptHeader = shouldEncryptHeader;
        }

        public JwtTokenProvider()
        {
            var section = _getConfigurationSection();

            _isConfigurationValid(section);

            JwtTimeout = _getTimeOut(section);
            EncryptionType = _getEncryptionType(section);
            ShouldEncryptHeader = _shouldEncryptHeader(section);
        }
        #endregion

        #region Events
        public delegate bool OnJtiValidateHandler(Guid jti);

        public event OnJtiValidateHandler OnJtiValidate;



        public delegate bool OnTokenValidateHandler(IJwtToken token);

        public event OnTokenValidateHandler OnTokenValidate;



        public delegate IJwtToken OnTokenCreateHandler(IJwtToken token);

        public event OnTokenCreateHandler OnCreate;



        public event OnSerializeHandler OnSerialize;

        public delegate string OnSerializeHandler(object toSerialize);



        public event OnDeserializeClaimsHandler OnDeserialize;

        public delegate Dictionary<string, object> OnDeserializeClaimsHandler(string jsonString);



        public event OnEncryptionHandler OnEncryption;

        public delegate byte[] OnEncryptionHandler(string toEncrypt, string secret);



        public event OnDecryptionHandler OnDecryption;

        public delegate string OnDecryptionHandler(byte[] encryptedBytes, string secret);



        public event OnGetConnectionIdHandler OnGetConnectionId;

        public delegate string OnGetConnectionIdHandler();
        #endregion

        #region Properties and Fields
        public readonly int JwtTimeout;

        public readonly JwtEncryption EncryptionType;

        public readonly bool ShouldEncryptHeader;
        #endregion

        #region Create
        public IJwtToken Create(Dictionary<string, object> extraHeaders, Dictionary<string, object> claims)
        {
            var token = new JwtToken(JwtTimeout);

            // set and add claims
            foreach (var claim in claims)
            {
                if (!token.ContainsClaimKey(claim.Key)) token.AddClaim(claim.Key);

                token.SetClaim(claim.Key, claim.Value);
            }

            // add extra headers
            foreach (var header in extraHeaders)
            {
                token.AddHeader(header.Key);
                token.SetHeader(header.Key, header.Value);
            }

            // try to add the custom connection id
            _tryAddCustomConnectionId(token);

            return token;
        }

        public IJwtToken Create()
        {
            var section = _getConfigurationSection();
            var timeOut = _getTimeOut(section);
            var token = new JwtToken(timeOut);

            // try to add the custom connection id
            _tryAddCustomConnectionId(token);

            return OnCreate != null ? OnCreate(token) : token;
        }

        private void _tryAddCustomConnectionId(JwtToken token)
        {
            // add the connection id to the claims
            if (OnGetConnectionId == null) return;

            token.AddHeader("cid");
            token.SetHeader("cid", OnGetConnectionId());
        }

        #endregion

        #region Configuration

        private IEncryptionSecret _getEncryptionSecret(JwtAuthConfigurationSection section)
        {
            return section.SingleEncryption.ElementInformation.IsPresent
                ? new SingleEncryptionSecret(section.SingleEncryption.Secret)
                : new TripleEncryptionSecret(section.TripleEncryption.SecretOne, section.TripleEncryption.SecretTwo,
                    section.TripleEncryption.SecretThree);
        }

        private JwtEncryption _getEncryptionType(JwtAuthConfigurationSection section)
        {
            if (section == null || (!section.SingleEncryption.ElementInformation.IsPresent && !section.TripleEncryption.ElementInformation.IsPresent)) return EncryptionType;

            return (JwtEncryption)Enum.Parse(typeof(JwtEncryption), section.SingleEncryption.ElementInformation.IsPresent ? section.SingleEncryption.Type : section.TripleEncryption.Type);
        }

        private bool _shouldEncryptHeader(JwtAuthConfigurationSection section)
        {
            if (section.SingleEncryption.ElementInformation.IsPresent)
            {
                return section.SingleEncryption.EncryptHeader.HasValue && section.SingleEncryption.EncryptHeader.Value;
            }

            if (section.TripleEncryption.ElementInformation.IsPresent)
            {
                return section.TripleEncryption.EncryptHeader.HasValue && section.TripleEncryption.EncryptHeader.Value;
            }

            return false;
        }

        private int _getTimeOut(JwtAuthConfigurationSection section)
        {
            if (!section.Token.ElementInformation.IsPresent) return JwtTimeout;

            return Convert.ToInt32(section.Token.TimeOut);
        }

        private JwtAuthConfigurationSection _getConfigurationSection()
        {
            return System.Configuration.ConfigurationManager.GetSection(JwtAuthConfigurationSection.SectionName) as JwtAuthConfigurationSection;
        }

        private void _isConfigurationValid(JwtAuthConfigurationSection section)
        {
            // get config section
            if (section == null) throw new JwtTokenException("Config error.  Jot config section missing.  Please use other constructor is you do not wish to use the config.");

            // check token

            if (string.IsNullOrEmpty(section.Token.TimeOut)) throw new JwtTokenException("Config error.  Token TimeOut is blank or missing");

            int value;

            if (!int.TryParse(section.Token.TimeOut, out value)) throw new JwtTokenException("Config error.  Token TimeOut is not an integer");

            // check encryption service

            if (!section.SingleEncryption.ElementInformation.IsPresent && !section.TripleEncryption.ElementInformation.IsPresent) throw new JwtTokenException("Config error.  Encryption missing.");

            if (section.SingleEncryption.ElementInformation.IsPresent && section.TripleEncryption.ElementInformation.IsPresent) throw new JwtTokenException("Config error.  Please only choose one encryption type (SingleEncryption or TripleEncryption).");

            if (section.SingleEncryption.ElementInformation.IsPresent)
            {
                if (section.SingleEncryption.Secret.Length < 12) throw new JwtTokenException("Config error.  Secret length must be at least 12 characters");

                if (string.IsNullOrEmpty(section.SingleEncryption.Type)) throw new JwtTokenException("Config error.  Single Encryption type is not set.");

                return;
            }

            if (section.TripleEncryption.SecretOne.Length < 12 || section.TripleEncryption.SecretTwo.Length < 12 || section.TripleEncryption.SecretThree.Length < 12) throw new JwtTokenException("Config error.  Secret length must be at least 12 characters");

            if (string.IsNullOrEmpty(section.TripleEncryption.Type)) throw new JwtTokenException("Config error.  Triple Encryption type is not set.");
        }

        #endregion

        #region Encode
        public string Encode(IJwtToken token, IEncryptionSecret encryption)
        {
            var jwt = token as JwtToken;

            if (jwt == null) throw new Exception("Token is not formed correctly");

            var tripleEncryption = encryption as TripleEncryptionSecret;

            return tripleEncryption != null ? _encode(token, tripleEncryption) : _encode(token, (SingleEncryptionSecret)encryption);
        }

        public bool _isEncryptionTwoWay()
        {
            switch (EncryptionType)
            {
                case JwtEncryption.AesHmac128:
                case JwtEncryption.AesHmac192:
                case JwtEncryption.AesHmac256:
                    return true;
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

        public string Encode(IJwtToken token)
        {
            var jwt = token as JwtToken;

            if (jwt == null) throw new Exception("Token is not formed correctly");

            var section = _getConfigurationSection();

            if (section == null) throw new Exception("No secret provided, please provide encryption secret");

            return Encode(token, _getEncryptionSecret(section));
        }

        private string _encode(IJwtToken token, SingleEncryptionSecret encryption)
        {
            return _encode(token, encryption.Secret, encryption.Secret, encryption.Secret, false);
        }

        private string _encode(IJwtToken token, TripleEncryptionSecret encryption)
        {
            return _encode(token, encryption.Secret, encryption.SecretTwo, encryption.SecretThree, true);
        }

        private string _encode(IJwtToken token, string secretOne, string secretTwo, string secretThree, bool useTripleEncryption)
        {
            var jwt = token as JwtToken;

            if (jwt == null) throw new Exception("Token is not formed correctly");

            jwt.SetHeader("alg", OnEncryption != null ? "Custom" : EncryptionType.ToString());

            // get the headers
            var jwtHeaders = jwt.GetHeaders();
            var jwtClaims = jwt.GetClaims();

            // serialize header and claims
            var header = _serializeObject(jwtHeaders);
            var claims = _serializeObject(jwtClaims);

            // header and claim bytes
            var headerBytes = Encoding.UTF8.GetBytes(header);
            var claimBytes = Encoding.UTF8.GetBytes(claims);

            // segments
            var headerSegment = UrlEncode.Base64UrlEncode(headerBytes);
            var claimSegment = UrlEncode.Base64UrlEncode(claimBytes);

            // encrypted Segments
            var headerSegmentEncrypted = _encrypt(headerSegment, secretTwo, EncryptionType);
            var claimsSegmentEncrypted = _encrypt(claimSegment, secretThree, EncryptionType);

            // sign the token
            var unsignedSignature = string.Concat(headerSegmentEncrypted, ".", claimsSegmentEncrypted);
            var signatureBytes = Encoding.UTF8.GetBytes(unsignedSignature);
            var encodedSignature = UrlEncode.Base64UrlEncode(signatureBytes);
            var signedSignature = _encrypt(encodedSignature, secretOne, EncryptionType);

            // get the final header segment
            var finalHeaderSegment = ShouldEncryptHeader ? _encrypt(headerSegment, secretOne, EncryptionType) : headerSegment;

            // return final result
            return string.Concat(finalHeaderSegment, ".", claimSegment, ".", signedSignature);
        }

        private string _createSignedSignature(string header, string claims, bool useTripleEncryption)
        {
        }

        #endregion

        #region Decode

        public IJwtToken Decode(string encodedToken)
        {
            var section = _getConfigurationSection();

            return Decode(encodedToken, _getEncryptionSecret(section));
        }

        public IJwtToken Decode(string encodedToken, IEncryptionSecret encryption)
        {
            try
            {
                var tripleEncryption = encryption as TripleEncryptionSecret;

                if (tripleEncryption != null)
                {
                    return _decode(encodedToken, tripleEncryption.Secret, tripleEncryption.SecretTwo, tripleEncryption.SecretThree);
                }

                var signleEncryption = (SingleEncryptionSecret) encryption;

                return _decode(encodedToken, signleEncryption.Secret, signleEncryption.Secret, signleEncryption.Secret);
            }
            catch (Exception ex)
            {
                // turn error into Jwt Exception
                throw new JwtTokenException(ex.Message);
            }
        }

        private class EncodedTokenHelper
        {
            private readonly string _encodedToken;

            public EncodedTokenHelper(string encodedToken)
            {
                _encodedToken = encodedToken;
            }

            private string[] _getParts()
            {
                if (string.IsNullOrEmpty(_encodedToken)) throw new Exception("Token is not formed correctly.  Token is null.");

                var parts = _encodedToken.Split('.');

                if (parts.Count() != 3) throw new Exception("Token is not formed correctly.  Must have 3 parts.");

                return parts;
            }


            public string GetDecodedHeader()
            {
                var parts = _getParts();

                return _uft8AndDecode(parts[0]);
            }

            public string GetDecodedClaims()
            {
                var parts = _getParts();

                return _uft8AndDecode(parts[1]);
            }

            public string GetSignature()
            {
                return _getParts()[2];
            }

            private string _uft8AndDecode(string value)
            {
                return Encoding.UTF8.GetString(UrlEncode.Base64UrlDecode(value));
            }
        }

        public IJwtToken _decode(string encodedToken, string secretOne, string secretTwo, string secretThree)
        {
            try
            {
                var tokenHelper = new EncodedTokenHelper(encodedToken);

                // decoded parts
                var decodedHeader = tokenHelper.GetDecodedHeader();
                var decodedClaims = tokenHelper.GetDecodedClaims();
                var signatureSegment = tokenHelper.GetSignature();

                // deserialize to object
                var claims = _deserialize(decodedClaims);

                if (!_isEncryptionTwoWay())
                {
                    // create signature

                    return new JwtToken(ShouldEncryptHeader ? null : _deserialize(decodedHeader), claims);
                }

                // finalize header
                var finalHeader = ShouldEncryptHeader ? _decrypt(UrlEncode.Base64UrlDecode(decodedHeader), secretOne, EncryptionType) : decodedHeader;

                // signature 
                var signatureCipherText = UrlEncode.Base64UrlDecode(signatureSegment);
                var signature = _decrypt(signatureCipherText, secretOne, EncryptionType);

                // make sure signature is correct
                var signatureParts = signature.Split('.');

                if (signatureParts.Count() != 2) throw new Exception("Token is not formed correctly.  Signature must have 2 parts.");

                var signatureHeader = signatureParts[0];
                var signatureClaims = signatureParts[1];

                // decrypt signature
                var decryptedSignatureHeader = _decrypt(UrlEncode.Base64UrlDecode(signatureHeader), secretTwo, EncryptionType);
                var decryptedSignatureClaims = _decrypt(UrlEncode.Base64UrlDecode(signatureClaims), secretThree, EncryptionType);

                // make sure signature header and claims match payload.  
                if (!string.Equals(decryptedSignatureHeader, finalHeader)) throw new Exception("Token claims from signature do not match claims from payload.  Claim has been tampered with.");

                if (!string.Equals(decryptedSignatureClaims, decodedClaims)) throw new Exception("Token header from signature do not match header from payload.  Claim has been tampered with.");

                var header = _deserialize(finalHeader);

                return new JwtToken(header, claims);
            }
            catch (Exception ex)
            {
                // turn error into Jwt Exception
                throw new JwtTokenException(ex.Message);
            }
        }

        public Dictionary<string, object> _deserialize(string jsonString)
        {
            return OnDeserialize != null ? OnDeserialize(jsonString) : Serializer.ToObject<Dictionary<string, object>>(jsonString);
        }

        private string _serializeObject(object entity)
        {
            return OnSerialize != null ? OnSerialize(entity) : Serializer.ToJSON(entity);
        }

        private string _encrypt(string message, string secret, JwtEncryption encryptionType)
        {
            if (OnEncryption != null) return UrlEncode.Base64UrlEncode(OnEncryption(message, secret));

            switch (encryptionType)
            {
                case JwtEncryption.AesHmac128:
                case JwtEncryption.AesHmac192:
                case JwtEncryption.AesHmac256:
                    return UrlEncode.Base64UrlEncode(AESThenHMAC.Encrypt(message, secret, encryptionType));
                default:
                    throw new ArgumentOutOfRangeException(nameof(encryptionType), encryptionType, null);
            }
        }


        private string _decrypt(byte[] cipherText, string secret, JwtEncryption encryptionType)
        {
            if (OnDecryption != null) return OnDecryption(cipherText, secret);

            switch (encryptionType)
            {
                case JwtEncryption.AesHmac128:
                case JwtEncryption.AesHmac192:
                case JwtEncryption.AesHmac256:
                    return Encoding.UTF8.GetString(UrlEncode.Base64UrlDecode(AESThenHMAC.Decrypt(cipherText, secret, encryptionType)));
                default:
                    throw new ArgumentOutOfRangeException(nameof(encryptionType), encryptionType, null);
            }
        }

        #endregion

        #region Refresh Token

        public IJwtToken Refresh(string encodedToken)
        {
            var token = Decode(encodedToken);

            return Refresh(token);
        }

        public IJwtToken Refresh(IJwtToken token)
        {
            var jwt = token as JwtToken;

            if (jwt == null) throw new Exception("Token is not formed correctly");

            var section = _getConfigurationSection();
            var timeOut = _getTimeOut(section);

            // refresh the expiration date
            jwt.SetClaim("exp", UnixDateServices.GetUnixTimestamp(timeOut));

            return token;
        }

        #endregion

        #region Validation

        public TokenValidationResult Validate(string encodedToken)
        {
            var section = _getConfigurationSection();
            var encryption = _getEncryptionSecret(section);

            return Validate(encodedToken, encryption);
        }

        public TokenValidationResult Validate(string encodedToken, JwtValidationContainer validationContainer)
        {
            var section = _getConfigurationSection();
            var encryption = _getEncryptionSecret(section);

            return Validate(encodedToken, encryption, null);
        }

        public TokenValidationResult Validate(string encodedToken, IEncryptionSecret encryption)
        {
            return Validate(encodedToken, encryption, null);
        }

        public TokenValidationResult Validate(string encodedToken, IEncryptionSecret encryption, JwtValidationContainer validationContainer)
        {
            try
            {
                var jwt = Decode(encodedToken, encryption);
                var jti = jwt.GetClaim<Guid>("jti");
                var nbf = jwt.GetClaim<double>("nbf");
                var exp = jwt.GetClaim<double>("exp");

                // check nbf
                var currentUnixTime = UnixDateServices.GetUnixTimestamp();
                var isNbfValid = true;

                if (validationContainer != null)
                {
                    if (validationContainer.CheckNfb)
                    {
                        // Not Before should not be before current time
                        isNbfValid = nbf < currentUnixTime;
                    }
                }
                else
                {
                    // Not Before should not be before current time
                    isNbfValid = nbf < currentUnixTime;
                }

                if (!isNbfValid) return TokenValidationResult.NotBeforeFailed;

                // check expiration date
                if (currentUnixTime >= exp) return TokenValidationResult.TokenExpired;

                // check the custom handler after everything.  
                // potentially saves in processing time if the claim is expired
                if (OnTokenValidate != null && !OnTokenValidate(jwt)) return TokenValidationResult.OnTokenValidateFailed;

                if (OnJtiValidate != null && !OnJtiValidate(jti)) return TokenValidationResult.OnJtiValidateFailed;

                if (validationContainer == null || !validationContainer.Any()) return TokenValidationResult.Passed;

                // perform custom checks
                foreach (var item in validationContainer)
                {
                    var claim = jwt.GetClaim(item.Key);

                    if (!object.Equals(claim, item.Value)) return TokenValidationResult.CustomCheckFailed;
                }

                return TokenValidationResult.Passed;
            }
            catch (Exception)
            {
                return TokenValidationResult.Other;
            }
        }

        #region General Checks

        // check nbf
        // check exp
        // check iat, cannot be 0

        #endregion

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
        public class JwtToken : IJwtToken
        {
            #region Properties And Fields

            private readonly Dictionary<string, object> _claims;

            private readonly Dictionary<string, object> _header;

            // headers
            private const string ALG = "alg"; // Encryption Algorithm
            private const string TYP = "typ"; // Type

            // claims
            private const string IAT = "iat"; // Issued At
            private const string EXP = "exp"; // Expiration Date
            private const string ROL = "rol"; // Role
            private const string JTI = "jti"; // Token Id
            private const string ISS = "iss"; // Issuer
            private const string AUD = "aud"; // Audience
            private const string NBF = "nbf"; // Not Before
            private const string USR = "usr"; // User
            private const string SUB = "sub"; // Subject

            #endregion

            #region Constructor

            public JwtToken(int jwtTimeOut)
            {
                _claims = new Dictionary<string, object>
                {
                    {IAT, UnixDateServices.GetUnixTimestamp()}, {EXP, UnixDateServices.GetUnixTimestamp(jwtTimeOut)}, {ROL, ""}, {JTI, Guid.NewGuid()}, {ISS, ""}, {AUD, ""}, {NBF, UnixDateServices.GetUnixTimestamp()}, {SUB, ""}, {USR, ""}
                };

                _header = new Dictionary<string, object>
                {
                    {ALG, ""}, {TYP, "JWT"}
                };
            }

            public JwtToken(Dictionary<string, object> header, Dictionary<string, object> claims)
            {
                _claims = claims;
                _header = header;
            }

            #endregion

            public void AddClaim(string claimKey)
            {
                _claims.Add(claimKey, "");
            }

            public bool ContainsClaimKey(string claimKey)
            {
                return _claims.ContainsKey(claimKey);
            }

            public void SetClaim(string claimKey, object value)
            {
                _claims[claimKey] = value;
            }

            public T GetHeader<T>(string headerKey)
            {
                return typeof(T) == typeof(Guid) ? (T) (dynamic) Guid.Parse(_header[headerKey].ToString()) : (T) Convert.ChangeType(_header[headerKey], typeof(T));
            }

            public object GetHeader(string headerKey)
            {
                return _header[headerKey];
            }

            public void SetHeader(string headerKey, object value)
            {
                _header[headerKey] = value;
            }

            public T GetClaim<T>(string claimKey)
            {
                return typeof(T) == typeof(Guid) ? (T) (dynamic) Guid.Parse(_claims[claimKey].ToString()) : (T) Convert.ChangeType(_claims[claimKey], typeof(T));
            }

            public object GetClaim(string claimKey)
            {
                return _claims[claimKey];
            }

            public void AddHeader(string headerKey)
            {
                _header.Add(headerKey, "");
            }

            public Dictionary<string, object> GetHeaders()
            {
                return _header;
            }

            public Dictionary<string, object> GetClaims()
            {
                return _claims;
            }
        }

        #endregion

        #region Encryption

        #region Encoding

        private static class UrlEncode
        {
            #region Url Encoding

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
                switch (s.Length%4) // Pad with trailing '='s
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
                        throw new System.Exception("Illegal base64url string!");
                }

                return Convert.FromBase64String(s); // Standard base64 decoder
            }

            #endregion
        }

        #endregion

        private static class AESThenHMAC
        {
            // From James Tuley.  Link: http://stackoverflow.com/questions/202011/encrypt-and-decrypt-a-string
            //Preconfigured Encryption Parameters
            private static readonly int _blockBitSize = 128;
            private static int _keyBitSize { get; set; }
            private static JwtEncryption _encryptionType { get; set; }

            //Preconfigured Password Key Derivation Parameters
            private static readonly int _saltBitSize = 64;
            private static readonly int _iterations = 10000;
            private static readonly int _minPasswordLength = 12;

            /// <summary>
            /// Simple Encryption (AES) then Authentication (HMAC) of a UTF8 message
            /// using Keys derived from a Password (PBKDF2).
            /// </summary>
            /// <param name="secretMessage">The secret message.</param>
            /// <param name="password">The password.</param>
            /// <param name="nonSecretPayload">The non secret payload.</param>
            /// <returns>
            /// Encrypted Message
            /// </returns>
            /// <exception cref="System.ArgumentException">password</exception>
            /// <remarks>
            /// Significantly less secure than using random binary keys.
            /// Adds additional non secret payload for key generation parameters.
            /// </remarks>
            public static byte[] Encrypt(string secretMessage, string password, JwtEncryption encryptionType, byte[] nonSecretPayload = null)
            {
                _encryptionType = encryptionType;
                _keyBitSize = (int) _encryptionType;

                if (string.IsNullOrEmpty(secretMessage))
                    throw new ArgumentException("Secret Message Required!", "secretMessage");

                var plainText = Encoding.UTF8.GetBytes(secretMessage);
                var cipherText = _simpleEncryptWithPassword(plainText, password, nonSecretPayload);
                return cipherText;
            }

            /// <summary>
            /// Simple Authentication (HMAC) and then Descryption (AES) of a UTF8 Message
            /// using keys derived from a password (PBKDF2). 
            /// </summary>
            /// <param name="encryptedMessage">The encrypted message.</param>
            /// <param name="password">The password.</param>
            /// <param name="nonSecretPayloadLength">Length of the non secret payload.</param>
            /// <returns>
            /// Decrypted Message
            /// </returns>
            /// <exception cref="System.ArgumentException">Encrypted Message Required!;encryptedMessage</exception>
            /// <remarks>
            /// Significantly less secure than using random binary keys.
            /// </remarks>
            public static string Decrypt(byte[] cipherText, string password, JwtEncryption encryptionType, int nonSecretPayloadLength = 0)
            {
                _encryptionType = encryptionType;
                _keyBitSize = (int) _encryptionType;

                if (cipherText == null) throw new ArgumentException("Encrypted Message Required!", "cipherText");

                var plainText = _simpleDecryptWithPassword(cipherText, password, nonSecretPayloadLength);
                return plainText == null ? null : Encoding.UTF8.GetString(plainText);
            }

            #region Helpers

            private static byte[] _simpleEncrypt(byte[] secretMessage, byte[] cryptKey, byte[] authKey, byte[] nonSecretPayload = null)
            {
                //User Error Checks
                if (cryptKey == null || cryptKey.Length != _keyBitSize/8)
                    throw new ArgumentException(String.Format("Key needs to be {0} bit!", _keyBitSize), "cryptKey");

                if (authKey == null || authKey.Length != _keyBitSize/8)
                    throw new ArgumentException(String.Format("Key needs to be {0} bit!", _keyBitSize), "authKey");

                if (secretMessage == null || secretMessage.Length < 1)
                    throw new ArgumentException("Secret Message Required!", "secretMessage");

                //non-secret payload optional
                nonSecretPayload = nonSecretPayload ?? new byte[] {};

                byte[] cipherText;
                byte[] iv;

                using (var aes = new AesManaged
                {
                    KeySize = _keyBitSize, BlockSize = _blockBitSize, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7
                })
                {
                    //Use random IV
                    aes.GenerateIV();
                    iv = aes.IV;

                    using (var encrypter = aes.CreateEncryptor(cryptKey, iv))
                    using (var cipherStream = new MemoryStream())
                    {
                        using (var cryptoStream = new CryptoStream(cipherStream, encrypter, CryptoStreamMode.Write))
                        using (var binaryWriter = new BinaryWriter(cryptoStream))
                        {
                            //Encrypt Data
                            binaryWriter.Write(secretMessage);
                        }

                        cipherText = cipherStream.ToArray();
                    }
                }

                //Assemble encrypted message and add authentication
                using (var hmac = new HMACSHA256(authKey))
                using (var encryptedStream = new MemoryStream())
                {
                    using (var binaryWriter = new BinaryWriter(encryptedStream))
                    {
                        //Prepend non-secret payload if any
                        binaryWriter.Write(nonSecretPayload);
                        //Prepend IV
                        binaryWriter.Write(iv);
                        //Write Ciphertext
                        binaryWriter.Write(cipherText);
                        binaryWriter.Flush();

                        //Authenticate all data
                        var tag = hmac.ComputeHash(encryptedStream.ToArray());
                        //Postpend tag
                        binaryWriter.Write(tag);
                    }
                    return encryptedStream.ToArray();
                }
            }

            private static byte[] _simpleDecrypt(byte[] encryptedMessage, byte[] cryptKey, byte[] authKey, int nonSecretPayloadLength = 0)
            {
                //Basic Usage Error Checks
                if (cryptKey == null || cryptKey.Length != _keyBitSize/8)
                    throw new ArgumentException(String.Format("CryptKey needs to be {0} bit!", _keyBitSize), "cryptKey");

                if (authKey == null || authKey.Length != _keyBitSize/8)
                    throw new ArgumentException(String.Format("AuthKey needs to be {0} bit!", _keyBitSize), "authKey");

                if (encryptedMessage == null || encryptedMessage.Length == 0)
                    throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");

                using (var hmac = new HMACSHA256(authKey))
                {
                    var sentTag = new byte[hmac.HashSize/8];
                    //Calculate Tag
                    var calcTag = hmac.ComputeHash(encryptedMessage, 0, encryptedMessage.Length - sentTag.Length);
                    var ivLength = (_blockBitSize/8);

                    //if message length is to small just return null
                    if (encryptedMessage.Length < sentTag.Length + nonSecretPayloadLength + ivLength)
                        return null;

                    //Grab Sent Tag
                    Array.Copy(encryptedMessage, encryptedMessage.Length - sentTag.Length, sentTag, 0, sentTag.Length);

                    //Compare Tag with constant time comparison
                    var compare = 0;
                    for (var i = 0; i < sentTag.Length; i++)
                        compare |= sentTag[i] ^ calcTag[i];

                    //if message doesn't authenticate return null
                    if (compare != 0)
                        return null;

                    using (var aes = new AesManaged
                    {
                        KeySize = _keyBitSize, BlockSize = _blockBitSize, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7
                    })
                    {
                        //Grab IV from message
                        var iv = new byte[ivLength];
                        Array.Copy(encryptedMessage, nonSecretPayloadLength, iv, 0, iv.Length);

                        using (var decrypter = aes.CreateDecryptor(cryptKey, iv))
                        using (var plainTextStream = new MemoryStream())
                        {
                            using (var decrypterStream = new CryptoStream(plainTextStream, decrypter, CryptoStreamMode.Write))
                            using (var binaryWriter = new BinaryWriter(decrypterStream))
                            {
                                //Decrypt Cipher Text from Message
                                binaryWriter.Write(encryptedMessage, nonSecretPayloadLength + iv.Length, encryptedMessage.Length - nonSecretPayloadLength - iv.Length - sentTag.Length);
                            }
                            //Return Plain Text
                            return plainTextStream.ToArray();
                        }
                    }
                }
            }

            private static byte[] _simpleEncryptWithPassword(byte[] secretMessage, string password, byte[] nonSecretPayload = null)
            {
                nonSecretPayload = nonSecretPayload ?? new byte[] {};

                //User Error Checks
                if (string.IsNullOrWhiteSpace(password) || password.Length < _minPasswordLength)
                    throw new ArgumentException(String.Format("Must have a password of at least {0} characters!", _minPasswordLength), "password");

                if (secretMessage == null || secretMessage.Length == 0)
                    throw new ArgumentException("Secret Message Required!", "secretMessage");

                var payload = new byte[((_saltBitSize/8)*2) + nonSecretPayload.Length];

                Array.Copy(nonSecretPayload, payload, nonSecretPayload.Length);
                int payloadIndex = nonSecretPayload.Length;

                byte[] cryptKey;
                byte[] authKey;
                //Use Random Salt to prevent pre-generated weak password attacks.
                using (var generator = new Rfc2898DeriveBytes(password, _saltBitSize/8, _iterations))
                {
                    var salt = generator.Salt;

                    //Generate Keys
                    cryptKey = generator.GetBytes(_keyBitSize/8);

                    //Create Non Secret Payload
                    Array.Copy(salt, 0, payload, payloadIndex, salt.Length);
                    payloadIndex += salt.Length;
                }

                //Deriving separate key, might be less efficient than using HKDF, 
                //but now compatible with RNEncryptor which had a very similar wireformat and requires less code than HKDF.
                using (var generator = new Rfc2898DeriveBytes(password, _saltBitSize/8, _iterations))
                {
                    var salt = generator.Salt;

                    //Generate Keys
                    authKey = generator.GetBytes(_keyBitSize/8);

                    //Create Rest of Non Secret Payload
                    Array.Copy(salt, 0, payload, payloadIndex, salt.Length);
                }

                return _simpleEncrypt(secretMessage, cryptKey, authKey, payload);
            }

            private static byte[] _simpleDecryptWithPassword(byte[] encryptedMessage, string password, int nonSecretPayloadLength = 0)
            {
                //User Error Checks
                if (string.IsNullOrWhiteSpace(password) || password.Length < _minPasswordLength)
                    throw new ArgumentException(String.Format("Must have a password of at least {0} characters!", _minPasswordLength), "password");

                if (encryptedMessage == null || encryptedMessage.Length == 0)
                    throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");

                var cryptSalt = new byte[_saltBitSize/8];
                var authSalt = new byte[_saltBitSize/8];

                //Grab Salt from Non-Secret Payload
                Array.Copy(encryptedMessage, nonSecretPayloadLength, cryptSalt, 0, cryptSalt.Length);
                Array.Copy(encryptedMessage, nonSecretPayloadLength + cryptSalt.Length, authSalt, 0, authSalt.Length);

                byte[] cryptKey;
                byte[] authKey;

                //Generate crypt key
                using (var generator = new Rfc2898DeriveBytes(password, cryptSalt, _iterations))
                {
                    cryptKey = generator.GetBytes(_keyBitSize/8);
                }
                //Generate auth key
                using (var generator = new Rfc2898DeriveBytes(password, authSalt, _iterations))
                {
                    authKey = generator.GetBytes(_keyBitSize/8);
                }

                return _simpleDecrypt(encryptedMessage, cryptKey, authKey, cryptSalt.Length + authSalt.Length + nonSecretPayloadLength);
            }

            #endregion
        }

        #endregion

        #region Date Services 

        private static class UnixDateServices
        {
            public static double GetUnixTimestamp(double jwtAuthorizationTimeOut)
            {
                var millisecondsTimeOut = ((jwtAuthorizationTimeOut*60)*1000);

                return Math.Round(GetUnixTimestamp() + millisecondsTimeOut);
            }

            private static DateTime _unixEpoch()
            {
                return new DateTime(1970, 1, 1).ToLocalTime();
            }

            public static double GetUnixTimestamp()
            {
                return Math.Round(DateTime.UtcNow.Subtract(_unixEpoch()).TotalSeconds);
            }

            public static DateTime ToDateTimeFromUnixEpoch(double unixTimestamp)
            {
                return _unixEpoch().AddSeconds(unixTimestamp);
            }
        }

        #endregion
    }
}
