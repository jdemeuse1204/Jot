using Jot.Attributes;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Shouldly;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Jot.Tests.Attributes
{
    [TestClass]
    public class RequiredTests
    {
        private JotProvider _provider;
        private string _encodedToken;
        private readonly string _secret = "secret";

        [TestInitialize]
        public void TestInitialize()
        {
            _provider = new JotProvider(30, HashAlgorithm.HS256);

            var claims = new Dictionary<string, object>
            {
                { "iss", "me" },
                { "tst", 1L }
            };

            _encodedToken = _provider.Encode(_provider.Create(claims), _secret);
        }

        [TestMethod]
        public void Should_ValidateClaim_AndSucceed()
        {
            var result = _provider.Validate<TestRequiredClaimRules>(_encodedToken, _secret);

            result.ShouldBe(TokenValidationResult.Passed);
        }

        [TestMethod]
        public void Should_ValidateClaimAndFailWhenClaimIsNotProvided_AndSucceed()
        {
            var claims = new Dictionary<string, object>
            {
                { "iss", "me" }
            };

            var encodedToken = _provider.Encode(_provider.Create(claims), _secret);

            var result = _provider.Validate<TestRequiredClaimRules>(encodedToken, _secret);

            result.ShouldBe(TokenValidationResult.ClaimMissing);
        }

        [TestMethod]
        public void Should_ValidateClaimAndFailWhenClaimIsProvidedButClaimIsNull_AndSucceed()
        {
            var claims = new Dictionary<string, object>
            {
                { "iss", "me" },
                { "tst", "" }
            };

            var encodedToken = _provider.Encode(_provider.Create(claims), _secret);

            var result = _provider.Validate<TestRequiredClaimRules>(encodedToken, _secret);

            result.ShouldBe(TokenValidationResult.CustomCheckFailed);
        }

        [TestMethod]
        public void Should_ThrowConciseErrorWhenNullableIsTheTargetType_AndSucceed()
        {
            try
            {
                var claims = new Dictionary<string, object>
                {
                    { "iss", "me" },
                    { "tst", "test" }
                };

                var encodedToken = _provider.Encode(_provider.Create(claims), _secret);

                var result = _provider.Validate<TestRequiredClaimRules>(encodedToken, _secret);

                result.ShouldBe(TokenValidationResult.CustomCheckFailed);
            }
            catch (JotException ex)
            {
                ex.Message.ShouldBe($"Cannot convert Claim {typeof(string).Name} to {typeof(long).Name}.  Claim Key: tst");
            }
        }
    }

    public class TestRequiredClaimRules
    {
        [Required]
        [VerifyClaim("tst")]
        public virtual TokenValidationResult Validate(long? claimValue)
        {
            return claimValue.HasValue ? TokenValidationResult.Passed : TokenValidationResult.CustomCheckFailed;
        }
    }
}
