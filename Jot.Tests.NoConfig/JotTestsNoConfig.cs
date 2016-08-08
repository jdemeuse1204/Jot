using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Linq;

namespace Jot.Tests.NoConfig
{
    [TestClass]
    public class JotTestsNoConfig
    {
        #region Tests Using the Configuration

        #region Token Creation

        [TestMethod]
        public void CreateClaimWithNoPayload()
        {
            var provider = new JwtTokenProvider(30, JwtEncryption.AesHmac256);

            var token = provider.Create();

            Assert.IsNotNull(token);
        }

        [TestMethod]
        public void CreateClaimWithPayload()
        {
            var provider = new JwtTokenProvider(30, JwtEncryption.AesHmac256);

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
            var provider = new JwtTokenProvider(30, JwtEncryption.AesHmac256);

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
            var provider = new JwtTokenProvider(30, JwtEncryption.AesHmac256);

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
            var provider = new JwtTokenProvider(30, JwtEncryption.AesHmac256);
            var encryptionPackage = new SingleEncryptionSecret("jsdfkjhsldjfls");

            var token = provider.Create();

            var jwt = provider.Encode(token, encryptionPackage);

            Assert.IsTrue(jwt.Split('.').Count() == 3);
        }
        #endregion

        #endregion
    }
}
