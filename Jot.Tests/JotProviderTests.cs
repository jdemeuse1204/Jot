using Microsoft.VisualStudio.TestTools.UnitTesting;
using Shouldly;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Jot.Tests
{
    [TestClass]
    public class JotProviderTests
    {
        private JotProvider _provider;
        private readonly string _secret = "secret";

        [TestInitialize]
        public void TestInitialize()
        {
            _provider = new JotProvider(30, HashAlgorithm.HS256);
        }

        [TestMethod, ExpectedException(typeof(NullReferenceException))]
        public void Should_NotValidateEncodedTokenWhenItIsNullOrEmpty_AndFail()
        {
            var result = _provider.Validate(null);
        }

        [TestMethod, ExpectedException(typeof(ArgumentNullException))]
        public void Should_NotValidateEncodedTokenWhenSecretIsNullOrEmpty_AndFail()
        {
            var claims = new Dictionary<string, object>
            {
                { "iss", "me" }
            };
            var encodedToken = _provider.Encode(_provider.Create(claims), _secret);
            var result = _provider.Validate(encodedToken, null);
        }

        [TestMethod]
        public void Should_UseOnHashCustomMethodWhenProvided_AndPass()
        {
            var provider = new JotProvider(30, HashAlgorithm.HS256);
            Func<byte[], string> encode = (byte[] payload) =>
            {
                var s = Convert.ToBase64String(payload); // Regular base64 encoder
                s = s.Split('=')[0]; // Remove any trailing '='s
                s = s.Replace('+', '-'); // 62nd char of encoding
                s = s.Replace('/', '_'); // 63rd char of encoding
                return s;
            };
            var callCount = 0;

            provider.OnHash += (byte[] toEncrypt, string secret) => 
            {
                callCount++;
                using (var sha = new HMACSHA256(Encoding.UTF8.GetBytes(secret)))
                {
                    return sha.ComputeHash(toEncrypt);
                }
            };

            var encodedToken = provider.Encode(provider.Create(), _secret);

            callCount.ShouldBe(1);
        }

        [TestMethod]
        public void Should_DeserializeClaims_AndSucceed()
        {
            var provider = new JotProvider(30, HashAlgorithm.HS256);
            var callCount = 0;

            provider.OnDeserialize += (string jsonString) =>
            {
                callCount++;
                return new Dictionary<string, object>();
            };

            var encodedToken = provider.Encode(provider.Create(), _secret);
            provider.Decode(encodedToken);

            // deserialzes header and claims
            callCount.ShouldBe(2);
        }

        [TestMethod]
        public void Should_SerializeClaims_AndSucceed()
        {
            var provider = new JotProvider(30, HashAlgorithm.HS256);
            var callCount = 0;

            provider.OnSerialize += (object toSerialize) =>
            {
                callCount++;
                return "test";
            };

            var encodedToken = provider.Encode(provider.Create(), _secret);

            // deserialzes header and claims
            callCount.ShouldBe(4);
        }

        [TestMethod]
        public void Should_CallOnCreate_AndSucceed()
        {
            var provider = new JotProvider(30, HashAlgorithm.HS256);
            var callCount = 0;

            provider.OnCreate += (IJotToken token) =>
            {
                callCount++;
            };

            provider.Create();

            // deserialzes header and claims
            callCount.ShouldBe(1);
        }
    }
}
