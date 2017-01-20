using System;
using System.Collections.Generic;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Jot.Tests.Common;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using Jot.Time;

namespace Jot.Tests
{
    #region Token Providers
    public class TestJwtTokenProvider : JotProvider
    {
        public TestJwtTokenProvider()
        {
            //OnCreate += OnOnCreate;
            OnDeserialize += OnOnDeserialize;
            OnSerialize += OnOnSerialize;

            OnCreate += (tkn) =>
            {
                tkn.SetClaim("tst", "SomeNewClaim");
            };

            OnDeserialize += jsonString => JsonConvert.DeserializeObject<Dictionary<string, object>>(jsonString);
            OnSerialize += serialize => JsonConvert.SerializeObject(serialize);
        }

        public string OnOnSerialize(object toSerialize)
        {
            return JsonConvert.SerializeObject(toSerialize);
        }

        public Dictionary<string, object> OnOnDeserialize(string jsonString)
        {
            return JsonConvert.DeserializeObject<Dictionary<string, object>>(jsonString);
        }

        public void OnOnCreate(IJotToken token)
        {
            token.SetClaim(JotDefaultClaims.ISS, "test");
        }
    }

    public class TestValidateJwtTokenProvider : JotProvider
    {
        public TestValidateJwtTokenProvider()
        {
            OnTokenValidate += OnOnTokenValidate;
        }

        private bool OnOnTokenValidate(IJotToken token)
        {
            var claimValue = token.GetClaim("tst");

            return object.Equals(claimValue, "win");
        }
    }

    public class TestGhostClaimTokenProvider : JotProvider
    {
        public TestGhostClaimTokenProvider()
                        : base(30, HashAlgorithm.HS512, true)
        {
            OnGetGhostClaims += OnOnGetGhostClaims;
        }

        private Dictionary<string, object> OnOnGetGhostClaims()
        {
            return new Dictionary<string, object> { { "cid", "test" } };
        }
    }


    public class TestHashJwtTokenProvider : JotProvider
    {
        public TestHashJwtTokenProvider()

        {
            OnHash += OnOnHash;
        }

        private byte[] OnOnHash(byte[] toEncrypt, string secret)
        {
            var key = Encoding.UTF8.GetBytes(secret);

            using (var sha = new HMACSHA384(key))
            {
                return sha.ComputeHash(toEncrypt);
            }
        }
    }

    public class TestJtiValidationClaimTokenProvider : JotProvider
    {
        private readonly Guid _jti;

        public TestJtiValidationClaimTokenProvider(Guid jti)
                        : base(30, HashAlgorithm.HS512, false)
        {
            this.OnJtiValidate += OnOnJtiValidate;
            _jti = jti;
        }

        private bool OnOnJtiValidate(Guid jti, IJotToken token)
        {
            return _jti == jti;
        }
    }
    #endregion

    [TestClass]
    public class JotEventTests
    {
        [TestMethod]
        public void CreateClaimWithNoPayload()
        {
            var provider = new TestJwtTokenProvider();

            var token = provider.Create();

            Assert.AreEqual(token.GetClaim<string>(JotDefaultClaims.ISS), "");
        }

        [TestMethod]
        public void VerifySerializationEventsWork()
        {
            var jot = new TestJwtTokenProvider();

            var token = jot.Create();

            var encodedToken = jot.Encode(token);

            var result = jot.Validate(encodedToken);

            Assert.AreEqual(result, TokenValidationResult.Passed);
        }

        [TestMethod]
        public void SetNbfToFutureDate()
        {
            var jot = new TestJwtTokenProvider();

            var token = jot.Create();

            token.SetClaim(JotDefaultClaims.NBF, UnixDateServices.GetUnixTimestamp(1));

            var encodedToken = jot.Encode(token);

            var result = jot.Validate(encodedToken);

            Assert.AreEqual(result, TokenValidationResult.NotBeforeFailed);
        }

        [TestMethod]
        public void MakeSureValidationContainerWorks()
        {
            var jot = new TestJwtTokenProvider();

            var token = jot.Create();

            token.SetClaim("tst", "win");

            var validationContainer = new JotValidationContainer();

            validationContainer.AddCustomClaimVerification("tst", "tst");

            var encodedToken = jot.Encode(token);

            var result = jot.Validate(encodedToken, validationContainer);

            Assert.AreEqual(result, TokenValidationResult.CustomCheckFailed);
        }

        [TestMethod]
        public void MakeSureOnTokenValidateWorks()
        {
            var jot = new TestValidateJwtTokenProvider();

            var token = jot.Create();

            token.SetClaim("tst", "some other value");

            var encodedToken = jot.Encode(token);

            var result = jot.Validate(encodedToken);

            Assert.AreEqual(result, TokenValidationResult.OnTokenValidateFailed);
        }

        [TestMethod]
        public void MakeSureEncryptionHandlerWorks()
        {
            var jot = new TestHashJwtTokenProvider();

            var token = jot.Create();

            var encodedToken = jot.Encode(token);

            var result = jot.Validate(encodedToken);

            Assert.AreEqual(result, TokenValidationResult.Passed);
        }

        [TestMethod]
        public void MakeSureGhostClaimsAreOnlyAddedToSignatureAndNotClaims()
        {
            var jot = new TestGhostClaimTokenProvider();
            var otherProvider = new JotProvider(30, HashAlgorithm.HS512);

            var token = jot.Create();
            var otherToken = otherProvider.Create();

            otherToken.SetClaim(JotDefaultClaims.EXP, token.GetClaim<double>(JotDefaultClaims.EXP));
            otherToken.SetClaim(JotDefaultClaims.NBF, token.GetClaim<double>(JotDefaultClaims.NBF));
            otherToken.SetClaim(JotDefaultClaims.IAT, token.GetClaim<double>(JotDefaultClaims.IAT));
            otherToken.SetClaim(JotDefaultClaims.JTI, token.GetClaim<Guid>(JotDefaultClaims.JTI));

            otherToken.SetHeader(JotDefaultHeaders.TYP, "JWT");
            otherToken.SetHeader(JotDefaultHeaders.ALG, "Anonymous");

            // must happen before reflection method, encode sets the encryption type
            var encodedToken = jot.Encode(token);

            var method = typeof(JotProvider).GetMethod("_getEncrytedSignature", BindingFlags.Instance | BindingFlags.NonPublic);

            var encryptedSignature = method.Invoke(jot, new object[] { token, "sjdfhikjsjhdkfjjhsdlkfhsakd" });
            var otherEncryptedSignature = method.Invoke(otherProvider, new object[] { otherToken, "sjdfhikjsjhdkfjjhsdlkfhsakd" });

            var signature = encodedToken.Split('.')[2];

            var decodedToken = jot.Decode(encodedToken);

            Assert.IsTrue(string.Equals(encryptedSignature, signature) && !decodedToken.ClaimExists("cid") && !string.Equals(encryptedSignature, otherEncryptedSignature));
        }

        [TestMethod]
        public void MakeSureJtiValidationWorks()
        {
            var jti = Guid.NewGuid();
            var jot = new TestJtiValidationClaimTokenProvider(jti);

            var token = jot.Create();

            token.SetClaim("jti", jti);

            var encodedToken = jot.Encode(token);

            var result = jot.Validate(encodedToken);

            Assert.AreEqual(result, TokenValidationResult.Passed);
        }

        [TestMethod]
        public void MakeSureJtiValidationWorks_PurposlyFail()
        {
            var jti = Guid.NewGuid();
            var jot = new TestJtiValidationClaimTokenProvider(jti);

            var token = jot.Create();

            token.SetClaim("jti", Guid.NewGuid());

            var encodedToken = jot.Encode(token);

            var result = jot.Validate(encodedToken);

            Assert.AreEqual(result, TokenValidationResult.OnJtiValidateFailed);
        }

        [TestMethod]
        public void MakeSureCustomValidationEventsWork()
        {
            var provider = new JotProvider();
            var validationContainer = new JotValidationContainer();
            var wasCustomValidationRun = false;
             
            validationContainer.AddCustomClaimVerification("tst", (claimValue) => 
            {
                wasCustomValidationRun = true;
                var tst = Convert.ToInt32(claimValue);

                return tst == 100;
            });

            var token = provider.Create();

            token.SetClaim("tst", 100);

            var encodedToken = provider.Encode(token);

            var validationResult = provider.Validate(encodedToken, validationContainer);

            Assert.IsTrue(validationResult == TokenValidationResult.Passed && wasCustomValidationRun);
        }

        [TestMethod]
        public void CanSkipNbfClaim_Pass()
        {
            var provider = new JotProvider();
            var validationContainer = new JotValidationContainer();

            validationContainer.SkipClaimVerification(JotDefaultClaims.EXP);

            var token = provider.Create();

            // set the exp equal to the nbf claim... which says its expired, then skip the exp claim
            var nbf = token.GetClaim<int>(JotDefaultClaims.NBF);
            token.SetClaim(JotDefaultClaims.EXP, nbf);

            var encodedToken = provider.Encode(token);

            var validationResult = provider.Validate(encodedToken, validationContainer);

            Assert.IsTrue(validationResult == TokenValidationResult.Passed);
        }

        [TestMethod]
        public void CanSkipNbfClaim_Fail()
        {
            var provider = new JotProvider();
            var validationContainer = new JotValidationContainer();

            var token = provider.Create();

            // set the exp equal to the nbf claim... which says its expired, then skip the exp claim
            var nbf = token.GetClaim<int>(JotDefaultClaims.NBF);
            token.SetClaim(JotDefaultClaims.EXP, nbf);

            var encodedToken = provider.Encode(token);

            var validationResult = provider.Validate(encodedToken, validationContainer);

            Assert.IsTrue(validationResult == TokenValidationResult.TokenExpired);
        }

        [TestMethod]
        public void SkipDefaultAndCustomProcessingAndAddCustomProcessingThatShouldBeSkipped()
        {
            var provider = new JotProvider();
            var timeProvider = new UnixTimeProvider();
            var validationContainer = new JotValidationContainer();
            var wasCustomValidationRun = false;

            // skip default processing
            validationContainer.SkipClaimVerification(JotDefaultClaims.NBF);

            // add custom processing
            validationContainer.AddCustomClaimVerification(JotDefaultClaims.NBF, (claimValue) =>
            {
                wasCustomValidationRun = true;
                return true;
            });

            var token = provider.Create();

            token.SetClaim(JotDefaultClaims.NBF, timeProvider.GetUnixTimestamp(60));

            var encodedToken = provider.Encode(token);

            var validationResult = provider.Validate(encodedToken, validationContainer);

            Assert.IsTrue(validationResult == TokenValidationResult.Passed && !wasCustomValidationRun);
        }

        [TestMethod]
        public void SkipDefaultProcessingAndAddCustomProcessingThatWasRun()
        {
            var provider = new JotProvider();
            var timeProvider = new UnixTimeProvider();
            var validationContainer = new JotValidationContainer();
            var wasCustomValidationRun = false;

            // add custom processing
            validationContainer.AddCustomClaimVerification(JotDefaultClaims.NBF, (claimValue) =>
            {
                wasCustomValidationRun = true;
                return true;
            });

            var token = provider.Create();

            token.SetClaim(JotDefaultClaims.NBF, timeProvider.GetUnixTimestamp(60));

            var encodedToken = provider.Encode(token);

            var validationResult = provider.Validate(encodedToken, validationContainer);

            Assert.IsTrue(validationResult == TokenValidationResult.Passed && wasCustomValidationRun);
        }
    }
}
