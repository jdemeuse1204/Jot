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
    public class InjectAdditionalClaimTests
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
                { "usr", "test" }
            };

            _encodedToken = _provider.Encode(_provider.Create(claims), _secret);
        }

        [TestMethod]
        public void Should_ValidateClaimWithInjectableClaim_AndSucceed()
        {
            var result = _provider.Validate<TestConversionInjectAdditionalClaimRules>(_encodedToken, _secret);

            result.ShouldBe(TokenValidationResult.Passed);
        }

        [TestMethod]
        public void Should_FailWhenConvertingInjectableClaimToTheWrongType()
        {
            try
            {
                var result = _provider.Validate<TestConversionFailInjectAdditionalClaimRules>(_encodedToken, _secret);
            }
            catch (JotException ex)
            {
                ex.Message.ShouldBe($"Cannot convert Additional Injected Claim {typeof(string).Name} to {typeof(int).Name}.  Additional Injected Claim Key: usr");
            }
        }

        [TestMethod]
        public void Should_FailWhenInjectableClaimIsMissing()
        {
            var result = _provider.Validate<TestFailInjectAdditionalClaimMissingRules>(_encodedToken, _secret);

            result.ShouldBe(TokenValidationResult.ClaimMissing);
        }
    }

    public class TestConversionInjectAdditionalClaimRules
    {
        [VerifyClaim("iss")]
        public virtual TokenValidationResult Validate(string claimValue, [InjectAdditionalClaim("usr")] string otherClaimValue)
        {
            return claimValue == "me" && otherClaimValue == "test" ? TokenValidationResult.Passed : TokenValidationResult.CustomCheckFailed;
        }
    }

    public class TestConversionFailInjectAdditionalClaimRules
    {
        [VerifyClaim("iss")]
        public virtual TokenValidationResult Validate(string claimValue, [InjectAdditionalClaim("usr")] int otherClaimValue)
        {
            return TokenValidationResult.Passed;
        }
    }

    public class TestFailInjectAdditionalClaimMissingRules
    {
        [VerifyClaim("iss")]
        public virtual TokenValidationResult Validate(string claimValue, [InjectAdditionalClaim("aaa")] int otherClaimValue)
        {
            return TokenValidationResult.Passed;
        }
    }
}
