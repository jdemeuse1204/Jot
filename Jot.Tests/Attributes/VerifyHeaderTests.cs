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
    public class VerifyHeaderTests
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
                { "iss", "me" }
            };

            var additionalHeaders = new Dictionary<string, object>
            {
                { "tst", "test" }
            };

            _encodedToken = _provider.Encode(_provider.Create(additionalHeaders, claims), _secret);
        }

        [TestMethod]
        public void Should_ValidateClaim_AndSucceed()
        {
            var result = _provider.Validate<TestGetHeaderRules>(_encodedToken, _secret);

            result.ShouldBe(TokenValidationResult.Passed);
            TestGetHeaderRules.ValidateRunCount.ShouldBe(1);
        }

        [TestMethod]
        public void Should_HaveErrorWhenConvertingClaimAndErrorMessageShouldSayWhichClaimAndWhatTheTypesAre()
        {
            try
            {
                var result = _provider.Validate<TestGetHeaderConversionRules>(_encodedToken, _secret);

                result.ShouldBe(TokenValidationResult.Passed);
            }
            catch (JotException ex)
            {
                ex.Message.ShouldBe($"Cannot convert Header Claim {typeof(string).Name} to {typeof(int).Name}.  Header Claim Key: tst");
            }
        }

        [TestMethod]
        public void Should_ValidateClaimWhenHeaderIsMissingAndThereIsNoRequiredAttribute_AndSucceed()
        {
            var result = _provider.Validate<TestMissingHeaderRules>(_encodedToken, _secret);

            result.ShouldBe(TokenValidationResult.Passed);
            TestMissingHeaderRules.ValidateRunCount.ShouldBe(0);
        }

        [TestMethod]
        public void Should_ValidateClaimWhenHeaderIsMissingAndThereIsARequiredAttribute_AndSucceed()
        {
            var result = _provider.Validate<TestRequiredHeaderRules>(_encodedToken, _secret);

            result.ShouldBe(TokenValidationResult.HeaderMissing);
            TestRequiredHeaderRules.ValidateRunCount.ShouldBe(0);
        }

        [TestMethod]
        public void Should_NotValidateHeaderClaimWhenAttributeIsMissing_AndSucceed()
        {
            var result = _provider.Validate<TestHeaderNoAttribute>(_encodedToken, _secret);

            result.ShouldBe(TokenValidationResult.Passed);
            TestHeaderNoAttribute.ValidateRunCount.ShouldBe(0);
        }
    }

    public class TestGetHeaderRules
    {
        public static int ValidateRunCount { get; set; }

        [VerifyHeader("tst")]
        public virtual TokenValidationResult Validate(string claimValue)
        {
            ValidateRunCount++;
            return claimValue == "test" ? TokenValidationResult.Passed : TokenValidationResult.CustomCheckFailed;
        }
    }

    public class TestGetHeaderConversionRules
    {
        [VerifyHeader("tst")]
        public virtual TokenValidationResult Validate(int claimValue)
        {
            return claimValue == 1 ? TokenValidationResult.Passed : TokenValidationResult.CustomCheckFailed;
        }
    }

    public class TestMissingHeaderRules
    {
        public static int ValidateRunCount { get; set; }
        
        [VerifyHeader("aaa")]
        public virtual TokenValidationResult Validate(int claimValue)
        {
            ValidateRunCount++;
            return claimValue == 1 ? TokenValidationResult.Passed : TokenValidationResult.CustomCheckFailed;
        }
    }

    public class TestRequiredHeaderRules
    {
        public static int ValidateRunCount { get; set; }

        [Required]
        [VerifyHeader("aaa")]
        public virtual TokenValidationResult Validate(int claimValue)
        {
            ValidateRunCount++;
            return claimValue == 1 ? TokenValidationResult.Passed : TokenValidationResult.CustomCheckFailed;
        }
    }

    public class TestHeaderNoAttribute
    {
        public static int ValidateRunCount { get; set; }

        public virtual TokenValidationResult Validate(int claimValue)
        {
            ValidateRunCount++;
            return claimValue == 1 ? TokenValidationResult.Passed : TokenValidationResult.CustomCheckFailed;
        }
    }
}
