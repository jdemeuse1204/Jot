using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using Jot.Tests.Common;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Shouldly;
using Jot.Time;

namespace Jot.Tests
{
    [TestClass]
    public class JotGeneralTests
    {
        private UnixTimeProvider _timeProvider => new UnixTimeProvider(new TimeProvider());

        [TestMethod]
        public void CreateClaimWithNoPayload()
        {
            var jot = new JotProvider();

            var token = jot.Create();

            Assert.IsNotNull(token);
        }

        [TestMethod]
        public void CreateClaimWithNoPayloadButAddAllDefaultClaims()
        {
            var jot = new JotProvider();

            var token = jot.Create();

            var claimOneFound = token.ClaimExists(JotDefaultClaims.IAT);
            var claimTwoFound = token.ClaimExists(JotDefaultClaims.EXP);
            var claimThreeFound = token.ClaimExists(JotDefaultClaims.JTI);
            var claimFourFound = token.ClaimExists(JotDefaultClaims.ISS);
            var claimFiveFound = token.ClaimExists(JotDefaultClaims.AUD);
            var claimSixFound = token.ClaimExists(JotDefaultClaims.NBF);
            var claimSevenFound = token.ClaimExists(JotDefaultClaims.SUB);

            claimOneFound.ShouldBe(true);
            claimTwoFound.ShouldBe(true);
            claimThreeFound.ShouldBe(true);
            claimFourFound.ShouldBe(true);
            claimFiveFound.ShouldBe(true);
            claimSixFound.ShouldBe(true);
            claimSevenFound.ShouldBe(true);
        }

        [TestMethod]
        public void CreateClaimWithPayload()
        {
            var jot = new JotProvider();

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

            var token = jot.Create(payload);

            Assert.IsNotNull(token);
        }

        [TestMethod]
        public void ShouldGetClaim()
        {
            var jot = new JotProvider();

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

            var token = jot.Create(payload);

            var role = token.GetClaim<string>("rol");

            role.ShouldBe("sdf");
        }

        [TestMethod]
        public void ShoulTrydGetClaim()
        {
            var jot = new JotProvider();

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

            var token = jot.Create(payload);
            object role;

            var wasFound = token.TryGetClaim("rol", out role);

            role.ToString().ShouldBe("sdf");
            wasFound.ShouldBe(true);
        }

        [TestMethod]
        public void ShouldGetClaimAndThrowError()
        {
            try
            {
                var jot = new JotProvider();

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

                var token = jot.Create(payload);
                var claim = token.GetClaim<string>("tst");

                Assert.IsTrue(false);
            }
            catch (Exception)
            {
                Assert.IsTrue(true);
            }
        }

        [TestMethod]
        public void ShouldGetClaimAndNotThrowError()
        {
            try
            {
                var jot = new JotProvider();

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

                var token = jot.Create(payload);
                object claim;
                var wasFound = token.TryGetClaim("tst", out claim);

                Assert.IsFalse(wasFound);
                Assert.IsNull(claim);
            }
            catch (Exception)
            {
                Assert.IsTrue(false);
            }
        }

        [TestMethod]
        public void CheckDefaultCreationValues()
        {
            var provider = new JotProvider();

            var token = provider.Create();

            var exp = token.GetClaim<double>("exp");
            var iat = token.GetClaim<double>("iat");
            var jti = token.GetClaim<Guid>("jti");
            var nbf = token.GetClaim<double>("nbf");

            iat.ShouldBeGreaterThan(0);
            nbf.ShouldBeGreaterThan(0);
            exp.ShouldBeGreaterThan(0);
            jti.ShouldNotBe(Guid.Empty);
        }

        [TestMethod]
        public void CreateClaimWithPayloadAndMakeSureValuesAreSet()
        {
            var jot = new JotProvider();

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

            var token = jot.Create(payload);

            var rol = token.GetClaim<string>("rol");
            var jti = token.GetClaim<Guid>("jti");
            var iss = token.GetClaim<string>("iss");

            Assert.IsTrue(string.Equals(rol, "Test") && string.Equals(iss, "Test") && jti == Guid.Empty);
        }

        [TestMethod]
        public void MakeSureClaimIsEncryptedCorrectly()
        {
            var jot = new JotProvider();

            var token = jot.Create();

            var jwt = jot.Encode(token);

            Assert.IsTrue(jwt.Split('.').Count() == 3);
        }

        [TestMethod]
        public void CheckNbf_AddTimeToSetTheNotBeforeToALaterDate()
        {
            var jot = new JotProvider();

            var unixTimestamp = _timeProvider.GetUnixTimestamp();

            var payload = new Dictionary<string, object>
            {
                {"iat", unixTimestamp},
                {"exp", unixTimestamp + 30 * 60},
                {"rol", "Test"},
                {"jti", Guid.Empty},
                {"iss", "Test"},
                {"aud", ""},
                {"nbf", (unixTimestamp + 10000)},
                {"sub", ""},
                {"usr", ""}
            };

            var token = jot.Create(payload);

            var jwt = jot.Encode(token);

            var isValid = jot.Validate(jwt);

            Assert.IsTrue(isValid == TokenValidationResult.NotBeforeFailed);
        }

        [TestMethod]
        public void CheckNbf_MakeSureItWorksOnItsOwn()
        {
            var jot = new JotProvider();

            var payload = new Dictionary<string, object>
            {
                {"iat", _timeProvider.GetUnixTimestamp()},
                {"exp", _timeProvider.GetUnixTimestamp(30)},
                {"rol", "Test"},
                {"jti", Guid.Empty},
                {"iss", "Test"},
                {"aud", ""},
                {"nbf", (_timeProvider.GetUnixTimestamp(0))},
                {"sub", ""},
            };

            var token = jot.Create(payload);

            var jwt = jot.Encode(token);

            var validationResult = jot.Validate(jwt);

            Assert.IsTrue(validationResult == TokenValidationResult.Passed);
        }

        [TestMethod]
        public void MakeSureExpClaimIsWorking()
        {
            var jot = new JotProvider();

            var token = jot.Create();

            var jwt = jot.Encode(token);

            Thread.Sleep(61000);

            var validationResult = jot.Validate(jwt);

            Assert.IsTrue(validationResult == TokenValidationResult.TokenExpired);
        }

        [TestMethod]
        public void MakeSureIatClaimIsWorking()
        {
            var jot = new JotProvider();

            var token = jot.Create();

            token.SetClaim(JotDefaultClaims.IAT, 0);

            var jwt = jot.Encode(token);

            var validationResult = jot.Validate(jwt);

            Assert.IsTrue(validationResult == TokenValidationResult.CreatedTimeCheckFailed);
        }

        [TestMethod]
        public void MakeSureIatClaimIsWorking_SetIatToFutureDate()
        {
            var jot = new JotProvider();

            var token = jot.Create();

            token.SetClaim(JotDefaultClaims.IAT, _timeProvider.GetUnixTimestamp(600));

            var jwt = jot.Encode(token);

            var validationResult = jot.Validate(jwt);

            Assert.IsTrue(validationResult == TokenValidationResult.CreatedTimeCheckFailed);
        }

        [TestMethod]
        public void MakeSureIatClaimIsWorking_SetIatToFutureDate_Skip()
        {
            var jot = new JotProvider();

            var token = jot.Create();

            token.SetClaim(JotDefaultClaims.IAT, _timeProvider.GetUnixTimestamp(600));

            var validationContainer = new JotValidationContainer();

            validationContainer.SkipClaimVerification(JotDefaultClaims.IAT);

            var jwt = jot.Encode(token);

            var validationResult = jot.Validate(jwt, validationContainer);

            Assert.IsTrue(validationResult == TokenValidationResult.Passed);
        }

        [TestMethod]
        public void MakeSureTimeProviderIsWorkingWhenInjectedIntoTheConstructor()
        {
            var jot = new JotProvider(_timeProvider);

            var token = jot.Create();

            var validationContainer = new JotValidationContainer();

            var jwt = jot.Encode(token);

            var validationResult = jot.Validate(jwt, validationContainer);

            Assert.IsTrue(validationResult == TokenValidationResult.Passed);
        }
    }
}
