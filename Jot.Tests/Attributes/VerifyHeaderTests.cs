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
            var mockRules = new Mock<TestGetHeaderRules>();

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
                var mockRules = new Mock<TestGetHeaderConversionRules>();

                var result = _provider.Validate(_encodedToken, _secret, mockRules.Object);

                result.ShouldBe(TokenValidationResult.Passed);
            }
            catch (JotException ex)
            {
                ex.Message.ShouldBe($"Cannot convert Header Claim {typeof(string).Name} to {typeof(int).Name}.  Header Claim Key: tst");
            }
        }
    }

    public class TestGetHeaderRules
    {
        [VerifyHeader("tst")]
        public virtual TokenValidationResult Validate(string claimValue)
        {
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
}
