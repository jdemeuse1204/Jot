using System;
using System.Collections.Generic;
using System.Linq;
using Jot.Tests.Common;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Jot.Tests
{
    [TestClass]
    public class JotGeneralTests
    {
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

            var payload = new Dictionary<string, object>
            {
                {"iat", 0},
                {"exp", 0},
                {"rol", "sdf"},
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
            var provider = new JwtTokenProvider();

            var token = provider.Create();

            var jwt = provider.Encode(token);

            Assert.IsTrue(jwt.Split('.').Count() == 3);
        }

        [TestMethod]
        public void CheckNbf_AddTimeToSetTheNotBeforeToALaterDate()
        {
            var provider = new JwtTokenProvider();

            var payload = new Dictionary<string, object>
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

            var payload = new Dictionary<string, object>
            {
                {"iat", UnixDateServices.GetUnixTimestamp()},
                {"exp", UnixDateServices.GetUnixTimestamp(30)},
                {"rol", "Test"},
                {"jti", Guid.Empty},
                {"iss", "Test"},
                {"aud", ""},
                {"sub", ""},
                {"usr", ""}
            };

            var token = provider.Create(payload);

            var jwt = provider.Encode(token);

            var validationResult = provider.Validate(jwt);

            Assert.IsTrue(validationResult == TokenValidationResult.Passed);
        }
    }
}
