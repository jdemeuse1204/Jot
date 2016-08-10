using System;
using System.Collections.Generic;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Jot.Tests.Common;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;

namespace Jot.Tests
{
    #region Token Providers
    public class TestJwtTokenProvider : JwtTokenProvider
    {
        public TestJwtTokenProvider()
        {
            OnCreate += OnOnCreate;
            OnDeserialize += OnOnDeserialize;
            OnSerialize += OnOnSerialize;
        }

        public string OnOnSerialize(object toSerialize)
        {
            return JsonConvert.SerializeObject(toSerialize);
        }

        public Dictionary<string, object> OnOnDeserialize(string jsonString)
        {
            return JsonConvert.DeserializeObject<Dictionary<string, object>>(jsonString);
        }

        public void OnOnCreate(IJwtToken token)
        {
            token.SetClaim(JwtDefaultClaims.ISS, "test");
        }
    }

    public class TestValidateJwtTokenProvider : JwtTokenProvider
    {
        public TestValidateJwtTokenProvider()
        {
            OnTokenValidate += OnOnTokenValidate;
        }

        private bool OnOnTokenValidate(IJwtToken token)
        {
            var claimValue = token.GetClaim("tst");

            return object.Equals(claimValue, "win");
        }
    }

    public class TestHashJwtTokenProvider : JwtTokenProvider
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

    public class TestGhostClaimTokenProvider : JwtTokenProvider
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

    public class TestJtiValidationClaimTokenProvider : JwtTokenProvider
    {
        private readonly Guid _jti;

        public TestJtiValidationClaimTokenProvider(Guid jti)
                        : base(30, HashAlgorithm.HS512, false)
        {
            this.OnJtiValidate += OnOnJtiValidate;
            _jti = jti;
        }

        private bool OnOnJtiValidate(Guid jti)
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

            Assert.AreEqual(token.GetClaim<string>(JwtDefaultClaims.ISS), "test");
        }

        [TestMethod]
        public void VerifySerializationEventsWork()
        {
            var provider = new TestJwtTokenProvider();

            var token = provider.Create();

            var encodedToken = provider.Encode(token);

            var result = provider.Validate(encodedToken);

            Assert.AreEqual(result, TokenValidationResult.Passed);
        }

        [TestMethod]
        public void SetNbfToFutureDate()
        {
            var provider = new TestJwtTokenProvider();

            var token = provider.Create();

            token.SetClaim(JwtDefaultClaims.NBF, UnixDateServices.GetUnixTimestamp(1));

            var encodedToken = provider.Encode(token);

            var result = provider.Validate(encodedToken);

            Assert.AreEqual(result, TokenValidationResult.NotBeforeFailed);
        }

        [TestMethod]
        public void MakeSureValidationContainerWorks()
        {
            var provider = new TestJwtTokenProvider();

            var token = provider.Create();

            token.SetClaim("tst", "win");

            var validationContainer = new JwtValidationContainer();

            validationContainer.CheckNfb = true;
            validationContainer.AddCustomCheck("tst", "tst");

            var encodedToken = provider.Encode(token);

            var result = provider.Validate(encodedToken, validationContainer);

            Assert.AreEqual(result, TokenValidationResult.CustomCheckFailed);
        }

        [TestMethod]
        public void MakeSureOnTokenValidateWorks()
        {
            var provider = new TestValidateJwtTokenProvider();

            var token = provider.Create();

            token.SetClaim("tst", "some other value");

            var encodedToken = provider.Encode(token);

            var result = provider.Validate(encodedToken);

            Assert.AreEqual(result, TokenValidationResult.OnTokenValidateFailed);
        }

        [TestMethod]
        public void MakeSureEncryptionHandlerWorks()
        {
            var provider = new TestHashJwtTokenProvider();

            var token = provider.Create();

            var encodedToken = provider.Encode(token);

            var result = provider.Validate(encodedToken);

            Assert.AreEqual(result, TokenValidationResult.Passed);
        }

        [TestMethod]
        public void MakeSureGhostClaimsAreOnlyAddedToSignatureAndNotClaims()
        {
            var provider = new TestGhostClaimTokenProvider();

            var token = provider.Create();

            // must happen before reflection method, encode sets the encryption type
            var encodedToken = provider.Encode(token);

            var method = typeof(JwtTokenProvider).GetMethod("_getEncrytedSignature", BindingFlags.Instance | BindingFlags.NonPublic);

            var encryptedSignature = method.Invoke(provider, new object[] { token, "sjdfhikjsjhdkfjjhsdlkfhsakd" });

            var signature = encodedToken.Split('.')[2];

            var decodedToken = provider.Decode(encodedToken);

            Assert.IsTrue(string.Equals(encryptedSignature, signature) && !decodedToken.ClaimExists("cid"));
        }

        [TestMethod]
        public void MakeSureJtiValidationWorks()
        {
            var jti = Guid.NewGuid();
            var provider = new TestJtiValidationClaimTokenProvider(jti);

            var token = provider.Create();

            token.SetClaim("jti", jti);

            var encodedToken = provider.Encode(token);

            var result = provider.Validate(encodedToken);

            Assert.AreEqual(result, TokenValidationResult.Passed);
        }

        [TestMethod]
        public void MakeSureJtiValidationWorks_PurposlyFail()
        {
            var jti = Guid.NewGuid();
            var provider = new TestJtiValidationClaimTokenProvider(jti);

            var token = provider.Create();

            token.SetClaim("jti", Guid.NewGuid());

            var encodedToken = provider.Encode(token);

            var result = provider.Validate(encodedToken);

            Assert.AreEqual(result, TokenValidationResult.OnJtiValidateFailed);
        }
    }
}
