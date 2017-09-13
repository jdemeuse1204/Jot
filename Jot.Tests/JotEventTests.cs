﻿using System;
using System.Collections.Generic;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Jot.Tests.Common;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using Jot.Rules;
using System.Threading;
using Jot.Attributes;

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

    public class TestJwtValidationRules
    {
        [VerifyClaim("tst")]
        public TokenValidationResult ValidateTstClaim(string claimValue)
        {
            return Equals(claimValue, "win") == false ? TokenValidationResult.OnTokenValidateFailed : TokenValidationResult.Passed;
        }
    }

    public class TestGhostClaimTokenProvider : JotProvider
    {
        public TestGhostClaimTokenProvider() : base(30, HashAlgorithm.HS512, true)
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

    public class TestValidateJtiRules
    {
        [VerifyClaim("jti")]
        public TokenValidationResult ValidateJti(Guid claimValue, [InjectFromPayload("jti")] Guid jti)
        {
            return claimValue == jti ? TokenValidationResult.Passed : TokenValidationResult.JtiValidateFailed;
        }
    }

    public class TestJtiValidationClaimTokenProvider : JotProvider
    {
        public TestJtiValidationClaimTokenProvider()
                        : base(30, HashAlgorithm.HS512, false)
        {
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

            Thread.Sleep(1000);

            var encodedToken = jot.Encode(token);

            var result = jot.Validate(encodedToken);

            Assert.AreEqual(result, TokenValidationResult.Passed);
        }

        [TestMethod]
        public void SetNbfToFutureDate()
        {
            var jot = new TestJwtTokenProvider();

            var token = jot.Create();

            Thread.Sleep(1000);

            token.SetClaim(JotDefaultClaims.NBF, UnixDateServices.GetUnixTimestamp(1));

            var encodedToken = jot.Encode(token);

            var result = jot.Validate(encodedToken);

            Assert.AreEqual(result, TokenValidationResult.NotBeforeFailed);
        }

        [TestMethod]
        public void MakeSureOnTokenValidateWorks()
        {
            var jot = new TestJwtTokenProvider();

            var token = jot.Create();

            token.SetClaim("tst", "some other value");

            var encodedToken = jot.Encode(token);

            var result = jot.Validate<TestJwtValidationRules>(encodedToken);

            Assert.AreEqual(result, TokenValidationResult.OnTokenValidateFailed);
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
            var jot = new TestJtiValidationClaimTokenProvider();

            var token = jot.Create();

            token.SetClaim("jti", jti);

            var encodedToken = jot.Encode(token);

            var result = jot.Validate<TestValidateJtiRules>(encodedToken, new { jti });

            Assert.AreEqual(result, TokenValidationResult.Passed);
        }


        [TestMethod]
        public void MakeSureJtiValidationWorks_PurposlyFail()
        {
            var jti = Guid.NewGuid();
            var jot = new TestJtiValidationClaimTokenProvider();

            var token = jot.Create();

            token.SetClaim("jti", jti);

            var encodedToken = jot.Encode(token);

            var result = jot.Validate<TestValidateJtiRules>(encodedToken, new { jti = Guid.NewGuid() });

            Assert.AreEqual(result, TokenValidationResult.JtiValidateFailed);
        }
    }
}
