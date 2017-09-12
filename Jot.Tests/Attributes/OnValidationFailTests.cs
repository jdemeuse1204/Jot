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
    public class OnValidationFailTests
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
        public void Should_OnFailShouldBeInvokedWhenValidationOfAClaimFails_AndSucceed()
        {
            var rules = new Mock<OnValidationFailRules>();

            rules.Setup(w => w.Validate(It.IsAny<long>())).Returns(TokenValidationResult.ClaimMissing);
            rules.Setup(w => w.Fail(It.IsAny<TokenValidationResult>(), It.IsAny<string>(), It.IsAny<object>()));

            var result = _provider.Validate(_encodedToken, _secret, rules.Object);

            result.ShouldBe(TokenValidationResult.ClaimMissing);
            rules.Verify(w => w.Validate(It.IsAny<long>()), Times.Once);
            rules.Verify(w => w.Fail(It.IsAny<TokenValidationResult>(), It.IsAny<string>(), It.IsAny<object>()), Times.Once);
        }


        [TestMethod]
        public void Should_OnFailShouldBeWhenClaimIsMissingAndClaimIsRequired_AndSucceed()
        {
            var rules = new Mock<OnValidationFailClaimMissingRules>();

            rules.Setup(w => w.Validate(It.IsAny<long>())).Returns(TokenValidationResult.ClaimMissing);
            rules.Setup(w => w.Fail(It.IsAny<TokenValidationResult>(), It.IsAny<string>(), It.IsAny<object>()));

            var result = _provider.Validate(_encodedToken, _secret, rules.Object);

            result.ShouldBe(TokenValidationResult.ClaimMissing);
            rules.Verify(w => w.Validate(It.IsAny<long>()), Times.Never);
            rules.Verify(w => w.Fail(It.IsAny<TokenValidationResult>(), It.IsAny<string>(), It.IsAny<object>()), Times.Once);
        }


        [TestMethod]
        public void Should_OnFailShouldNotBeInvokesWhenClaimIsMissingAndClaimIsNotRequired_AndSucceed()
        {
            var rules = new Mock<OnValidationFailClaimMissingAndNotRequiredRules>();

            rules.Setup(w => w.Validate(It.IsAny<long>())).Returns(TokenValidationResult.ClaimMissing);
            rules.Setup(w => w.Fail(It.IsAny<TokenValidationResult>(), It.IsAny<string>(), It.IsAny<object>()));

            var result = _provider.Validate(_encodedToken, _secret, rules.Object);

            result.ShouldBe(TokenValidationResult.Passed);
            rules.Verify(w => w.Validate(It.IsAny<long>()), Times.Never);
            rules.Verify(w => w.Fail(It.IsAny<TokenValidationResult>(), It.IsAny<string>(), It.IsAny<object>()), Times.Never);
        }

        [TestMethod]
        public void Should_OnFailShouldBeWhenHeaderIsMissingAndHeaderIsRequired_AndSucceed()
        {
            var rules = new Mock<OnValidationFailHeaderMissingRules>();

            rules.Setup(w => w.Validate(It.IsAny<long>())).Returns(TokenValidationResult.ClaimMissing);
            rules.Setup(w => w.Fail(It.IsAny<TokenValidationResult>(), It.IsAny<string>(), It.IsAny<object>()));

            var result = _provider.Validate(_encodedToken, _secret, rules.Object);

            result.ShouldBe(TokenValidationResult.HeaderMissing);
            rules.Verify(w => w.Validate(It.IsAny<long>()), Times.Never);
            rules.Verify(w => w.Fail(It.IsAny<TokenValidationResult>(), It.IsAny<string>(), It.IsAny<object>()), Times.Once);
        }

        [TestMethod]
        public void Should_OnFailShouldNotBeInvokesWhenHeaderIsMissingAndHeaderIsNotRequired_AndSucceed()
        {
            var rules = new Mock<OnValidationFailHeaderMissingAndNotRequiredRules>();

            rules.Setup(w => w.Validate(It.IsAny<long>())).Returns(TokenValidationResult.ClaimMissing);
            rules.Setup(w => w.Fail(It.IsAny<TokenValidationResult>(), It.IsAny<string>(), It.IsAny<object>()));

            var result = _provider.Validate(_encodedToken, _secret, rules.Object);

            result.ShouldBe(TokenValidationResult.Passed);
            rules.Verify(w => w.Validate(It.IsAny<long>()), Times.Never);
            rules.Verify(w => w.Fail(It.IsAny<TokenValidationResult>(), It.IsAny<string>(), It.IsAny<object>()), Times.Never);
        }
    }

    public class OnValidationFailRules
    {
        [Required]
        [VerifyClaim("tst")]
        public virtual TokenValidationResult Validate(long claimValue)
        {
            return claimValue == 1 ? TokenValidationResult.ClaimMissing : TokenValidationResult.Passed;
        }

        [OnValidationFail]
        public virtual void Fail(TokenValidationResult result, string claimKey, object claimValue)
        {
            
        }
    }

    public class OnValidationFailClaimMissingRules
    {
        [Required]
        [VerifyClaim("aaa")]
        public virtual TokenValidationResult Validate(long claimValue)
        {
            return claimValue == 1 ? TokenValidationResult.ClaimMissing : TokenValidationResult.Passed;
        }

        [OnValidationFail]
        public virtual void Fail(TokenValidationResult result, string claimKey, object claimValue)
        {

        }
    }

    public class OnValidationFailClaimMissingAndNotRequiredRules
    {
        [VerifyClaim("aaa")]
        public virtual TokenValidationResult Validate(long claimValue)
        {
            return claimValue == 1 ? TokenValidationResult.ClaimMissing : TokenValidationResult.Passed;
        }

        [OnValidationFail]
        public virtual void Fail(TokenValidationResult result, string claimKey, object claimValue)
        {

        }
    }

    public class OnValidationFailHeaderMissingRules
    {
        [Required]
        [VerifyHeader("aaa")]
        public virtual TokenValidationResult Validate(long claimValue)
        {
            return claimValue == 1 ? TokenValidationResult.ClaimMissing : TokenValidationResult.Passed;
        }

        [OnValidationFail]
        public virtual void Fail(TokenValidationResult result, string claimKey, object claimValue)
        {

        }
    }

    public class OnValidationFailHeaderMissingAndNotRequiredRules
    {
        [VerifyClaim("aaa")]
        public virtual TokenValidationResult Validate(long claimValue)
        {
            return claimValue == 1 ? TokenValidationResult.ClaimMissing : TokenValidationResult.Passed;
        }

        [OnValidationFail]
        public virtual void Fail(TokenValidationResult result, string claimKey, object claimValue)
        {

        }
    }
}
