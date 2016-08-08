using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Jot.Tests
{
    #region Helpers
    public static class UnixDateServices
    {
        public static double GetUnixTimestamp(double jwtAuthorizationTimeOut)
        {
            var millisecondsTimeOut = ((jwtAuthorizationTimeOut * 60) * 1000);

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

    public static class Serializer
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

    #region Encryption

    #region Encoding

    public static class UrlEncode
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

    public static class AESThenHMAC
    {
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
            _keyBitSize = (int)_encryptionType;

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
    #endregion

    [TestClass]
    public class JotTests
    {
        #region Tests Using the Configuration

        #region Token Creation

        [TestMethod]
        public void CreateClaimWithNoPayload()
        {
            var provider = new JwtTokenProvider();

            var token = provider.Create();

            Assert.IsNotNull(token);
        }

        [TestMethod]
        public void CreateClaimWithPayload()
        {
            var provider = new JwtTokenProvider();

            var payload = new JwtClaimPayload
            {
                {"iat", ""},
                {"exp", ""},
                {"rol", ""},
                {"jti", ""},
                {"iss", ""},
                {"aud", ""},
                {"nbf", ""},
                {"sub", ""},
                {"usr", ""}
            };

            var token = provider.Create(payload);

            Assert.IsNotNull(token);
        }

        [TestMethod]
        public void CheckDefaultCreationValues()
        {
            var provider = new JwtTokenProvider();

            var token = provider.Create();

            var exp = token.GetClaim<double>("exp");
            var iat = token.GetClaim<double>("iat");
            var jti = token.GetClaim<Guid>("jti");
            var nbf = token.GetClaim<double>("nbf");

            Assert.IsTrue(exp > 0 && iat > 0 && nbf > 0 && jti != Guid.Empty);
        }

        [TestMethod]
        public void CreateClaimWithPayloadAndMakeSureValuesAreSet()
        {
            var provider = new JwtTokenProvider();

            var payload = new JwtClaimPayload
            {
                {"iat", ""},
                {"exp", ""},
                {"rol", "Test"},
                {"jti", Guid.Empty},
                {"iss", "Test"},
                {"aud", ""},
                {"nbf", ""},
                {"sub", ""},
                {"usr", ""}
            };

            var token = provider.Create(payload);

            var rol = token.GetClaim<string>("rol");
            var jti = token.GetClaim<Guid>("jti");
            var iss = token.GetClaim<string>("iss");

            Assert.IsTrue(string.Equals(rol, "Test") && string.Equals(iss, "Test") && jti == Guid.Empty);
        }

        [TestMethod]
        public void MakeSureClaimIsEncryptedCorrectly()
        {
            var provider = new JwtTokenProvider();

            var token = provider.Create();

            var jwt = provider.Encode(token);

            Assert.IsTrue(jwt.Split('.').Count() == 3);
        }

        [TestMethod]
        public void CheckNbf_AddTimeToSetTheNotBeforeToALaterDate()
        {
            var provider = new JwtTokenProvider();

            var payload = new JwtClaimPayload
            {
                {"iat", UnixDateServices.GetUnixTimestamp()},
                {"exp", UnixDateServices.GetUnixTimestamp(30)},
                {"rol", "Test"},
                {"jti", Guid.Empty},
                {"iss", "Test"},
                {"aud", ""},
                {"nbf", (UnixDateServices.GetUnixTimestamp(0) + 10000)},
                {"sub", ""},
                {"usr", ""}
            };

            var token = provider.Create(payload);

            var jwt = provider.Encode(token);

            var isValid = provider.Validate(jwt);

            Assert.IsTrue(isValid == TokenValidationResult.NotBeforeFailed);
        }

        [TestMethod]
        public void CheckNbf_MakeSureItWorksOnItsOwn()
        {
            var provider = new JwtTokenProvider();

            var payload = new JwtClaimPayload
            {
                {"iat", UnixDateServices.GetUnixTimestamp()},
                {"exp", UnixDateServices.GetUnixTimestamp(30)},
                {"rol", "Test"},
                {"jti", Guid.Empty},
                {"iss", "Test"},
                {"aud", ""},
                {"nbf", (UnixDateServices.GetUnixTimestamp(0))},
                {"sub", ""},
                {"usr", ""}
            };

            var token = provider.Create(payload);

            var jwt = provider.Encode(token);

            var isValid = provider.Validate(jwt);

            Assert.IsTrue(isValid == TokenValidationResult.Passed);
        }

        #region Event Checking

        //OnJtiValidate     
        //OnTokenValidate
        //OnCreate
        //OnSerialize
        //OnDeserialize
        //OnEncryption
        //OnDecryption

        [TestMethod]
        public void MakeSureOnCreateEventWorks()
        {
            var provider = new JwtTokenProvider();
            var wasOnCreateRun = false;

            provider.OnCreate += () =>
            {
                wasOnCreateRun = true;

                return new JwtClaimPayload
                {
                    {"iat", UnixDateServices.GetUnixTimestamp()},
                    {"exp", UnixDateServices.GetUnixTimestamp(30)},
                    {"rol", "MakeSureCreateEventWorks"},
                    {"jti", Guid.Empty},
                    {"iss", "Test"},
                    {"aud", ""},
                    {"nbf", UnixDateServices.GetUnixTimestamp()},
                    {"sub", ""},
                    {"usr", ""}
                };
            };

            var token = provider.Create();

            var rol = token.GetClaim<string>("rol");

            Assert.IsTrue(string.Equals(rol, "MakeSureCreateEventWorks") && wasOnCreateRun);
        }

        [TestMethod]
        public void MakeSureOnJtiValidateEventWorks()
        {
            var provider = new JwtTokenProvider();
            var wasOnJtiValidateRun = false;

            provider.OnCreate += () => new JwtClaimPayload
            {
                {"iat", UnixDateServices.GetUnixTimestamp()},
                {"exp", UnixDateServices.GetUnixTimestamp(30)},
                {"rol", "MakeSureCreateEventWorks"},
                {"jti", Guid.Empty},
                {"iss", "Test"},
                {"aud", ""},
                {"nbf", UnixDateServices.GetUnixTimestamp()},
                {"sub", ""},
                {"usr", ""}
            };

            // fail the jti check
            provider.OnJtiValidate += jti =>
            {
                wasOnJtiValidateRun = true;
                return false;
            };

            var token = provider.Create();

            var encoded = provider.Encode(token);

            var validationResult = provider.Validate(encoded);

            Assert.IsTrue(validationResult == TokenValidationResult.OnJtiValidateFailed);
        }

        [TestMethod]
        public void MakeSureOnTokenValidateEventWorks()
        {
            var provider = new JwtTokenProvider();
            var wasOnTokenValidateRun = false;

            provider.OnCreate += () => new JwtClaimPayload
            {
                {"iat", UnixDateServices.GetUnixTimestamp()},
                {"exp", UnixDateServices.GetUnixTimestamp(30)},
                {"rol", "MakeSureCreateEventWorks"},
                {"jti", Guid.Empty},
                {"iss", "Test"},
                {"aud", ""},
                {"nbf", UnixDateServices.GetUnixTimestamp()},
                {"sub", ""},
                {"usr", ""}
            };

            // fail the validate check
            provider.OnTokenValidate += jwtToken =>
            {
                wasOnTokenValidateRun = true;
                return false;
            };

            var token = provider.Create();

            var encoded = provider.Encode(token);

            var validationResult = provider.Validate(encoded);

            Assert.IsTrue(validationResult == TokenValidationResult.OnTokenValidateFailed && wasOnTokenValidateRun);
        }

        [TestMethod]
        public void MakeSureOnSerializeEventsWorks()
        {
            var provider = new JwtTokenProvider();
            var wasSerializationRun = false;
            var wasDeserializeHeaderRun = false;
            var wasDeserializeClaimsRun = false;

            provider.OnCreate += () => new JwtClaimPayload
            {
                {"iat", UnixDateServices.GetUnixTimestamp()},
                {"exp", UnixDateServices.GetUnixTimestamp(30)},
                {"rol", "MakeSureOnSerializeWorks"},
                {"jti", Guid.Empty},
                {"iss", "Test"},
                {"aud", ""},
                {"nbf", UnixDateServices.GetUnixTimestamp()},
                {"sub", ""},
                {"usr", ""}
            };

            // fail the validate check
            provider.OnSerialize += serialize =>
            {
                wasSerializationRun = true;
                return Serializer.ToJSON(serialize);
            };
            provider.OnDeserializeClaims += jsonString =>
            {
                wasDeserializeClaimsRun = true;
                return
                    Serializer.ToObject<Dictionary<string, object>>(
                        jsonString);
            };
            provider.OnDeserializeHeader += jsonString =>
            {
                wasDeserializeHeaderRun = true;
                return
                    Serializer.ToObject<Dictionary<string, string>>(
                        jsonString);
            };

            var token = provider.Create();

            var encoded = provider.Encode(token);

            var test = provider.Decode(encoded);

            var role = test.GetClaim<string>("rol");

            Assert.IsTrue(string.Equals(role, "MakeSureOnSerializeWorks") && wasDeserializeClaimsRun && wasDeserializeHeaderRun && wasSerializationRun);
        }

        [TestMethod]
        public void MakeSureEncryptionEventsWork()
        {
            var provider = new JwtTokenProvider();
            var wasEncryptionRun = false;
            var wasDecryptionRun = false;

            provider.OnCreate += () => new JwtClaimPayload
            {
                {"iat", UnixDateServices.GetUnixTimestamp()},
                {"exp", UnixDateServices.GetUnixTimestamp(30)},
                {"rol", "MakeSureOnSerializeWorks"},
                {"jti", Guid.Empty},
                {"iss", "Test"},
                {"aud", ""},
                {"nbf", UnixDateServices.GetUnixTimestamp()},
                {"sub", ""},
                {"usr", ""}
            };

            // fail the validate check
            provider.OnEncryption += (encrypt, secret) =>
            {
                wasEncryptionRun = true;
                return AESThenHMAC.Encrypt(encrypt, secret, JwtEncryption.AesHmac256);
            };
            provider.OnDecryption += (encryptedString, secret) =>
            {
                wasDecryptionRun = true;
                return AESThenHMAC.Decrypt(encryptedString, secret, JwtEncryption.AesHmac256);
            };
            

            var token = provider.Create();

            var encoded = provider.Encode(token);

            var test = provider.Decode(encoded);

            var role = test.GetClaim<string>("rol");

            Assert.IsTrue(string.Equals(role, "MakeSureOnSerializeWorks") && wasEncryptionRun && wasDecryptionRun);
        }
        #endregion

        #endregion

        #endregion
    }
}
