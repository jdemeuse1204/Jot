using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Linq;

namespace Jot.Tests.NoConfig
{
    [TestClass]
    public class JotTestsNoConfig
    {
        [TestMethod]
        public void CreateClaimWithNoPayload()
        {
            var provider = new JwtTokenProvider(30, HashAlgorithm.HS512);

            var token = provider.Create();

            Assert.IsNotNull(token);
        }

        [TestMethod]
        public void CreateClaimWithPayload()
        {
            var provider = new JwtTokenProvider(30, HashAlgorithm.HS512);

            var payload = new Dictionary<string, object>
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
            var provider = new JwtTokenProvider(30, HashAlgorithm.HS512);

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
            var provider = new JwtTokenProvider(30, HashAlgorithm.HS512);

            var payload = new Dictionary<string, object>
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
            var provider = new JwtTokenProvider(30, HashAlgorithm.HS512);

            provider.OnCreate += (jwt) =>
            {
                jwt.SetClaim("iss", "IssuedByMe!");
            };

            var token = provider.Create();

            var encodedToken = provider.Encode(token, "kjsdkfjgosdjfgoi");

            Assert.IsTrue(encodedToken.Split('.').Count() == 3);
        }
    }
}
