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
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace Jot
{
    public class JwtTokenProvider
    {
        #region Constructor
        public JwtTokenProvider(int jwtTimeOutInMinutes, JwtEncryption encryptionType)
        {
            JwtTimeout = jwtTimeOutInMinutes;
            EncryptionType = encryptionType;
        }

        public JwtTokenProvider()
        {
            var section = _getConfigurationSection();

            _isConfigurationValid(section);

            JwtTimeout = _getTimeOut(section);
            EncryptionType = _getEncryptionType(section);
        }
        #endregion

        #region Events
        public delegate bool OnJtiValidateHandler(Guid jti);

        public event OnJtiValidateHandler OnJtiValidate;



        public delegate bool OnTokenValidateHandler(IJwtToken token);

        public event OnTokenValidateHandler OnTokenValidate;



        public delegate JwtClaimPayload OnTokenCreateHandler();

        public event OnTokenCreateHandler OnCreate;



        public event OnSerializeHandler OnSerialize;

        public delegate string OnSerializeHandler(object toSerialize);



        public event OnDeserializeHeaderHandler OnDeserializeHeader;

        public delegate Dictionary<string, string> OnDeserializeHeaderHandler(string jsonString);



        public event OnDeserializeClaimsHandler OnDeserializeClaims;

        public delegate Dictionary<string, object> OnDeserializeClaimsHandler(string jsonString);



        public event OnEncryptionHandler OnEncryption;

        public delegate byte[] OnEncryptionHandler(string toEncrypt, string secret);



        public event OnDecryptionHandler OnDecryption;

        public delegate string OnDecryptionHandler(string encryptedString, string secret);
        #endregion

        #region Properties and Fields
        public readonly int JwtTimeout;

        public readonly JwtEncryption EncryptionType;
        #endregion

        #region Create
        public IJwtToken Create(JwtClaimPayload claims)
        {
            var token = new JwtToken(JwtTimeout);

            foreach (var claim in claims)
            {
                if (!token.ContainsClaimKey(claim.Key)) token.AddClaim(claim.Key);

                token.SetClaim(claim.Key, claim.Value);
            }

            return token;
        }

        public IJwtToken Create()
        {
            return Create(OnCreate != null ? OnCreate() : new JwtClaimPayload());
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

            return (JwtEncryption)Enum.ToObject(typeof(JwtEncryption), Convert.ToInt32(section.SingleEncryption.ElementInformation.IsPresent ? section.SingleEncryption.Type : section.TripleEncryption.Type));
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

        #region Encode/Decode

        public IJwtToken Decode(string encodedToken)
        {
            var section = _getConfigurationSection();

            return Decode(encodedToken, _getEncryptionSecret(section));
        }

        public IJwtToken Decode(string encodedToken, IEncryptionSecret encryption)
        {
            try
            {
                if (string.IsNullOrEmpty(encodedToken)) throw new JwtTokenException("Token is not valid.  Encoded token is null");

                // split claim into header, payload, and signature
                var parts = encodedToken.Split('.');

                // make sure claim is correctly formed
                if (parts.Length != 3) throw new JwtTokenException("Token is not valid.  Does not consist of three parts");

                // get encoded parts
                var encodedHeader = parts[0];
                var encodedClaims = parts[1];
                var encodedSignature = parts[2];

                var tripleEncryption = encryption as TripleEncryptionSecret;
                var singleEncryption = (SingleEncryptionSecret)encryption;

                // secrets
                var isUsingTripleEncryption = tripleEncryption != null;
                var secretOne = singleEncryption.Secret;
                var secretTwo = isUsingTripleEncryption ? tripleEncryption.SecretTwo : secretOne;
                var secretThree = isUsingTripleEncryption ? tripleEncryption.SecretThree : secretOne;

                // decoded parts
                var decodedHeader = OnDecryption != null ? OnDecryption(encodedHeader, secretOne) : AESThenHMAC.Decrypt(encodedHeader, secretOne, EncryptionType);
                var decodedClaims = OnDecryption != null ? OnDecryption(encodedClaims, secretTwo) : AESThenHMAC.Decrypt(encodedClaims, secretTwo, EncryptionType);
                var decodedSignature = OnDecryption != null ? OnDecryption(encodedSignature, secretThree) : AESThenHMAC.Decrypt(encodedSignature, secretThree, EncryptionType);

                if (string.IsNullOrEmpty(decodedHeader)) throw new JwtTokenException("Token is not valid.  Header failed to decode");

                if (string.IsNullOrEmpty(decodedClaims)) throw new JwtTokenException("Token is not valid.  Claims failed to decode");

                if (string.IsNullOrEmpty(decodedSignature)) throw new JwtTokenException("Token is not valid.  Signature failed to decode");

                // split the signature
                var signatureParts = decodedSignature.Split('.');

                // make sure signature is correctly formed
                if (signatureParts.Length != 2) throw new JwtTokenException("Token is not valid.  Signature incorrect");

                // get encoded signature parts
                var encodedHeaderFromSignature = signatureParts[0];
                var encodedClaimsFromSignature = signatureParts[1];

                // decode signature parts
                var decodedHeaderFromSignature = OnDecryption != null ? OnDecryption(encodedHeaderFromSignature, secretOne) : AESThenHMAC.Decrypt(encodedHeaderFromSignature, secretOne, EncryptionType);
                var decodedClaimsFromSignature = OnDecryption != null ? OnDecryption(encodedClaimsFromSignature, secretTwo) : AESThenHMAC.Decrypt(encodedClaimsFromSignature, secretTwo, EncryptionType);

                // verify the signature - check header
                if (!string.Equals(decodedHeaderFromSignature, decodedHeader)) throw new JwtTokenException("Token is not valid.  Signature verification failed, header does not match");

                // verify the signature - check claims
                if (!string.Equals(decodedClaimsFromSignature, decodedClaims)) throw new JwtTokenException("Token is not valid.  Signature verification failed, claims do not match");

                var header = OnDeserializeHeader != null ? OnDeserializeHeader(decodedHeader) : Serializer.ToObject<Dictionary<string, string>>(decodedHeader);
                var claims = OnDeserializeClaims != null ? OnDeserializeClaims(decodedClaims) : Serializer.ToObject<Dictionary<string, object>>(decodedClaims);

                return new JwtToken(header, claims);
            }
            catch (Exception ex)
            {
                // turn error into Jwt Exception
                throw new JwtTokenException(ex.Message);
            }
        }

        public string Encode(IJwtToken token, IEncryptionSecret encryption)
        {
            var jwt = token as JwtToken;

            if (jwt == null) throw new Exception("Token is not formed correctly");

            return _encode(token, encryption);
        }

        public string Encode(IJwtToken token)
        {
            var jwt = token as JwtToken;

            if (jwt == null) throw new Exception("Token is not formed correctly");

            var section = _getConfigurationSection();

            if (section == null) throw new Exception("No secret provided, please provide encryption secret");

            return _encode(token, _getEncryptionSecret(section));
        }

        private string _encode(IJwtToken token, IEncryptionSecret encryption)
        {
            var jwt = token as JwtToken;
            var section = _getConfigurationSection();
            var encryptionType = _getEncryptionType(section);

            if (jwt == null) throw new Exception("Token is not formed correctly");

            jwt.SetHeader("alg", encryptionType.ToString());

            var jwtHeaders = jwt.GetHeaders();
            var jwtClaims = jwt.GetClaims();

            // serialize header and claims
            var header = OnSerialize != null ? OnSerialize(jwtHeaders) : Serializer.ToJSON(jwtHeaders);
            var claims = OnSerialize != null ? OnSerialize(jwtClaims) : Serializer.ToJSON(jwtClaims);

            var tripleEncryption = encryption as TripleEncryptionSecret;
            var singleEncryption = (SingleEncryptionSecret)encryption;

            // secrets
            var isUsingTripleEncryption = tripleEncryption != null;
            var secretOne = singleEncryption.Secret;
            var secretTwo = isUsingTripleEncryption ? tripleEncryption.SecretTwo : secretOne;
            var secretThree = isUsingTripleEncryption ? tripleEncryption.SecretThree : secretOne;

            // encrypt
            var encryptedHeader = OnEncryption != null ? UrlEncode.Base64UrlEncode(OnEncryption(header, secretOne)) : AESThenHMAC.Encrypt(header, secretOne, encryptionType);
            var encryptedClaims = OnEncryption != null ? UrlEncode.Base64UrlEncode(OnEncryption(claims, secretTwo)) : AESThenHMAC.Encrypt(claims, secretTwo, encryptionType);

            // create payload
            var payload = string.Concat(encryptedHeader, ".", encryptedClaims);

            // create signature
            var signature = OnEncryption != null ? UrlEncode.Base64UrlEncode(OnEncryption(payload, secretThree)) : AESThenHMAC.Encrypt(payload, secretThree, encryptionType);

            // return final result
            return string.Concat(payload, ".", signature);
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

            private readonly Dictionary<string, string> _header;

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

            public JwtToken(ITimeProvider timeProvider, int jwtTimeOut)
            {
                _claims = new Dictionary<string, object>
                {
                    {IAT, timeProvider.GetUnixTimestamp()},
                    {EXP, timeProvider.GetUnixTimestamp(jwtTimeOut)},
                    {ROL, ""},
                    {JTI, Guid.NewGuid()},
                    {ISS, ""},
                    {AUD, ""},
                    {NBF, timeProvider.GetUnixTimestamp()},
                    {SUB, ""},
                    {USR, ""}
                };

                _header = new Dictionary<string, string>
                {
                    {ALG, ""},
                    {TYP, "JWT"}
                };
            }

            /// <summary>
            /// Initializes a new instance of the <see cref="JwtToken"/> class.
            /// </summary>
            /// <param name="jwtTimeOut">The JWT time out in minutes.</param>
            public JwtToken(int jwtTimeOut) : this(new TimeProvider(), jwtTimeOut)
            {
            }

            public JwtToken(Dictionary<string, string> header, Dictionary<string, object> claims)
            {
                _claims = claims;
                _header = header;
            }

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

            public T GetClaim<T>(string claimKey)
            {
                return typeof(T) == typeof(Guid) ? (T)(dynamic)Guid.Parse(_claims[claimKey].ToString()) : (T)Convert.ChangeType(_claims[claimKey], typeof(T));
            }

            public object GetClaim(string claimKey)
            {
                return _claims[claimKey];
            }

            public void SetHeader(string claimKey, string value)
            {
                _header[claimKey] = value;
            }

            public Dictionary<string, string> GetHeaders()
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
                switch (s.Length % 4) // Pad with trailing '='s
                {
                    case 0: break; // No pad chars in this case
                    case 2: s += "=="; break; // Two pad chars
                    case 3: s += "="; break; // One pad char
                    default:
                        throw new System.Exception(
                 "Illegal base64url string!");
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
            public static string Encrypt(string secretMessage, string password, JwtEncryption encryptionType, byte[] nonSecretPayload = null)
            {
                _encryptionType = encryptionType;
                _keyBitSize = (int)_encryptionType;

                if (string.IsNullOrEmpty(secretMessage))
                    throw new ArgumentException("Secret Message Required!", "secretMessage");

                var plainText = Encoding.UTF8.GetBytes(secretMessage);
                var cipherText = _simpleEncryptWithPassword(plainText, password, nonSecretPayload);
                return UrlEncode.Base64UrlEncode(cipherText);
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
            public static string Decrypt(string encryptedMessage, string password, JwtEncryption encryptionType,
                                     int nonSecretPayloadLength = 0)
            {
                _encryptionType = encryptionType;
                _keyBitSize = (int)_encryptionType;

                if (string.IsNullOrWhiteSpace(encryptedMessage))
                    throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");

                var cipherText = UrlEncode.Base64UrlDecode(encryptedMessage);
                var plainText = _simpleDecryptWithPassword(cipherText, password, nonSecretPayloadLength);
                return plainText == null ? null : Encoding.UTF8.GetString(plainText);
            }

            #region Helpers
            private static byte[] _simpleEncrypt(byte[] secretMessage, byte[] cryptKey, byte[] authKey, byte[] nonSecretPayload = null)
            {
                //User Error Checks
                if (cryptKey == null || cryptKey.Length != _keyBitSize / 8)
                    throw new ArgumentException(String.Format("Key needs to be {0} bit!", _keyBitSize), "cryptKey");

                if (authKey == null || authKey.Length != _keyBitSize / 8)
                    throw new ArgumentException(String.Format("Key needs to be {0} bit!", _keyBitSize), "authKey");

                if (secretMessage == null || secretMessage.Length < 1)
                    throw new ArgumentException("Secret Message Required!", "secretMessage");

                //non-secret payload optional
                nonSecretPayload = nonSecretPayload ?? new byte[] { };

                byte[] cipherText;
                byte[] iv;

                using (var aes = new AesManaged
                {
                    KeySize = _keyBitSize,
                    BlockSize = _blockBitSize,
                    Mode = CipherMode.CBC,
                    Padding = PaddingMode.PKCS7
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
                if (cryptKey == null || cryptKey.Length != _keyBitSize / 8)
                    throw new ArgumentException(String.Format("CryptKey needs to be {0} bit!", _keyBitSize), "cryptKey");

                if (authKey == null || authKey.Length != _keyBitSize / 8)
                    throw new ArgumentException(String.Format("AuthKey needs to be {0} bit!", _keyBitSize), "authKey");

                if (encryptedMessage == null || encryptedMessage.Length == 0)
                    throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");

                using (var hmac = new HMACSHA256(authKey))
                {
                    var sentTag = new byte[hmac.HashSize / 8];
                    //Calculate Tag
                    var calcTag = hmac.ComputeHash(encryptedMessage, 0, encryptedMessage.Length - sentTag.Length);
                    var ivLength = (_blockBitSize / 8);

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
                        KeySize = _keyBitSize,
                        BlockSize = _blockBitSize,
                        Mode = CipherMode.CBC,
                        Padding = PaddingMode.PKCS7
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
                                binaryWriter.Write(
                                  encryptedMessage,
                                  nonSecretPayloadLength + iv.Length,
                                  encryptedMessage.Length - nonSecretPayloadLength - iv.Length - sentTag.Length
                                );
                            }
                            //Return Plain Text
                            return plainTextStream.ToArray();
                        }
                    }
                }
            }

            private static byte[] _simpleEncryptWithPassword(byte[] secretMessage, string password, byte[] nonSecretPayload = null)
            {
                nonSecretPayload = nonSecretPayload ?? new byte[] { };

                //User Error Checks
                if (string.IsNullOrWhiteSpace(password) || password.Length < _minPasswordLength)
                    throw new ArgumentException(String.Format("Must have a password of at least {0} characters!", _minPasswordLength), "password");

                if (secretMessage == null || secretMessage.Length == 0)
                    throw new ArgumentException("Secret Message Required!", "secretMessage");

                var payload = new byte[((_saltBitSize / 8) * 2) + nonSecretPayload.Length];

                Array.Copy(nonSecretPayload, payload, nonSecretPayload.Length);
                int payloadIndex = nonSecretPayload.Length;

                byte[] cryptKey;
                byte[] authKey;
                //Use Random Salt to prevent pre-generated weak password attacks.
                using (var generator = new Rfc2898DeriveBytes(password, _saltBitSize / 8, _iterations))
                {
                    var salt = generator.Salt;

                    //Generate Keys
                    cryptKey = generator.GetBytes(_keyBitSize / 8);

                    //Create Non Secret Payload
                    Array.Copy(salt, 0, payload, payloadIndex, salt.Length);
                    payloadIndex += salt.Length;
                }

                //Deriving separate key, might be less efficient than using HKDF, 
                //but now compatible with RNEncryptor which had a very similar wireformat and requires less code than HKDF.
                using (var generator = new Rfc2898DeriveBytes(password, _saltBitSize / 8, _iterations))
                {
                    var salt = generator.Salt;

                    //Generate Keys
                    authKey = generator.GetBytes(_keyBitSize / 8);

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

                var cryptSalt = new byte[_saltBitSize / 8];
                var authSalt = new byte[_saltBitSize / 8];

                //Grab Salt from Non-Secret Payload
                Array.Copy(encryptedMessage, nonSecretPayloadLength, cryptSalt, 0, cryptSalt.Length);
                Array.Copy(encryptedMessage, nonSecretPayloadLength + cryptSalt.Length, authSalt, 0, authSalt.Length);

                byte[] cryptKey;
                byte[] authKey;

                //Generate crypt key
                using (var generator = new Rfc2898DeriveBytes(password, cryptSalt, _iterations))
                {
                    cryptKey = generator.GetBytes(_keyBitSize / 8);
                }
                //Generate auth key
                using (var generator = new Rfc2898DeriveBytes(password, authSalt, _iterations))
                {
                    authKey = generator.GetBytes(_keyBitSize / 8);
                }

                return _simpleDecrypt(encryptedMessage, cryptKey, authKey, cryptSalt.Length + authSalt.Length + nonSecretPayloadLength);
            }
            #endregion
        }
        #endregion

        #region Date Services 

        private static class UnixDateServices
        {
            /// <summary>
            /// Gets the unix timestamp.
            /// </summary>
            /// <param name="jwtAuthorizationTimeOut">The JWT authorization time out in minutes.</param>
            /// <returns></returns>
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
