using Jot.Attributes;
using Jot.Time;
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
    public class VerifyClaimTests
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

            _encodedToken = _provider.Encode(_provider.Create(claims), _secret);
        }

        [TestMethod]
        public void Should_ValidateClaim_AndSucceed()
        {
            var result = _provider.Validate<TestGetClaimRules>(_encodedToken, _secret);

            result.ShouldBe(TokenValidationResult.Passed);
            TestGetClaimRules.ValidateRunCount.ShouldBe(1);
        }

        [TestMethod]
        public void Should_HaveErrorWhenConvertingClaimAndErrorMessageShouldSayWhichClaimAndWhatTheTypesAre()
        {
            try
            {
                var result = _provider.Validate<TestConversionRules>(_encodedToken, _secret);

                result.ShouldBe(TokenValidationResult.Passed);
            }
            catch (JotException ex)
            {
                ex.Message.ShouldBe($"Cannot convert Claim {typeof(string).Name} to {typeof(int).Name}.  Claim Key: iss");
            }
        }

        [TestMethod]
        public void Should_ValidateClaimWhenClaimIsMissingAndThereIsNoRequiredAttribute_AndSucceed()
        {
            var result = _provider.Validate<TestConversionWhenClaimMissingRules>(_encodedToken, _secret);

            result.ShouldBe(TokenValidationResult.Passed);
            TestConversionWhenClaimMissingRules.ValidateRunCount.ShouldBe(0);
        }

        [TestMethod]
        public void Should_ValidateClaimWhenClaimIsMissingAndThereIsARequiredAttribute_AndSucceed()
        {
            var result = _provider.Validate<TestConversionWhenClaimRequiredRules>(_encodedToken, _secret);

            result.ShouldBe(TokenValidationResult.ClaimMissing);
            TestConversionWhenClaimRequiredRules.ValidateRunCount.ShouldBe(0);
        }

        [TestMethod]
        public void Should_NotValidateClaimWhenAttributeIsMissing_AndSucceed()
        {
            var result = _provider.Validate<TestClaimVerificationWhenNoAttributePresent>(_encodedToken, _secret);

            result.ShouldBe(TokenValidationResult.Passed);
            TestClaimVerificationWhenNoAttributePresent.ValidateRunCount.ShouldBe(0);
        }
    }

    public class TestGetClaimRules
    {
        public static int ValidateRunCount { get; set; }

        [VerifyClaim("iss")]
        public virtual TokenValidationResult Validate(string claimValue)
        {
            ValidateRunCount++;
            return !string.IsNullOrEmpty(claimValue) ? TokenValidationResult.Passed : TokenValidationResult.CustomCheckFailed;
        }
    }

    public class TestConversionRules
    {
        public static int ValidateRunCount { get; set; }

        [VerifyClaim("iss")]
        public virtual TokenValidationResult Validate(int claimValue)
        {
            ValidateRunCount++;
            return TokenValidationResult.Passed;
        }
    }

    public class TestConversionWhenClaimMissingRules
    {
        public static int ValidateRunCount { get; set; }

        [VerifyClaim("tst")]
        public virtual TokenValidationResult Validate(int claimValue)
        {
            ValidateRunCount++;
            return TokenValidationResult.Passed;
        }
    }

    public class TestConversionWhenClaimRequiredRules
    {
        public static int ValidateRunCount { get; set; }

        [Required]
        [VerifyClaim("tst")]
        public virtual TokenValidationResult Validate(int claimValue)
        {
            ValidateRunCount++;
            return TokenValidationResult.Passed;
        }
    }

    public class TestClaimVerificationWhenNoAttributePresent
    {
        public static int ValidateRunCount { get; set; }

        public virtual TokenValidationResult Validate(int claimValue)
        {
            ValidateRunCount++;
            return TokenValidationResult.Passed;
        }
    }
}
