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
            var mockRules = new Mock<TestGetClaimRules>();

            mockRules.Setup(w => w.Validate(It.IsAny<string>())).Returns(TokenValidationResult.Passed);

            var result = _provider.Validate(_encodedToken, _secret, mockRules.Object);

            result.ShouldBe(TokenValidationResult.Passed);
            mockRules.Verify(w => w.Validate(It.IsAny<string>()));
        }

        [TestMethod]
        public void Should_HaveErrorWhenConvertingClaimAndErrorMessageShouldSayWhichClaimAndWhatTheTypesAre()
        {
            try
            {
                var mockRules = new Mock<TestConversionRules>();

                var result = _provider.Validate(_encodedToken, _secret, mockRules.Object);

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
            var mockRules = new Mock<TestConversionWhenClaimMissingRules>();

            mockRules.Setup(w => w.Validate(It.IsAny<int>())).Returns(TokenValidationResult.Passed);

            var result = _provider.Validate(_encodedToken, _secret, mockRules.Object);

            result.ShouldBe(TokenValidationResult.Passed);
            mockRules.Verify(w => w.Validate(It.IsAny<int>()), Times.Never);
        }
    }

    public class TestGetClaimRules
    {
        [VerifyClaim("iss")]
        public virtual TokenValidationResult Validate(string claimValue)
        {
            return !string.IsNullOrEmpty(claimValue) ? TokenValidationResult.Passed : TokenValidationResult.CustomCheckFailed;
        }
    }

    public class TestConversionRules
    {
        [VerifyClaim("iss")]
        public virtual TokenValidationResult Validate(int claimValue)
        {
            return TokenValidationResult.Passed;
        }
    }

    public class TestConversionWhenClaimMissingRules
    {
        [VerifyClaim("tst")]
        public virtual TokenValidationResult Validate(int claimValue)
        {
            return TokenValidationResult.Passed;
        }
    }
}
