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
            var result = _provider.Validate<OnValidationFailRules>(_encodedToken, _secret);

            OnValidationFailRules.FailRunCount.ShouldBe(1);
            OnValidationFailRules.ValidateRunCount.ShouldBe(1);
            result.ShouldBe(TokenValidationResult.ClaimMissing);
        }


        [TestMethod]
        public void Should_OnFailShouldBeWhenClaimIsMissingAndClaimIsRequired_AndSucceed()
        {
            var result = _provider.Validate<OnValidationFailClaimMissingRules>(_encodedToken, _secret);

            OnValidationFailClaimMissingRules.ValidateRunCount.ShouldBe(0);
            OnValidationFailClaimMissingRules.FailRunCount.ShouldBe(1);
            result.ShouldBe(TokenValidationResult.ClaimMissing);
        }


        [TestMethod]
        public void Should_OnFailShouldNotBeInvokesWhenClaimIsMissingAndClaimIsNotRequired_AndSucceed()
        {
            var result = _provider.Validate<OnValidationFailClaimMissingAndNotRequiredRules>(_encodedToken, _secret);

            result.ShouldBe(TokenValidationResult.Passed);
            OnValidationFailClaimMissingAndNotRequiredRules.ValidateRunCount.ShouldBe(0);
            OnValidationFailClaimMissingAndNotRequiredRules.FailRunCount.ShouldBe(0);
        }

        [TestMethod]
        public void Should_OnFailShouldBeWhenHeaderIsMissingAndHeaderIsRequired_AndSucceed()
        {
            var result = _provider.Validate<OnValidationFailHeaderMissingRules>(_encodedToken, _secret);

            result.ShouldBe(TokenValidationResult.HeaderMissing);
            OnValidationFailHeaderMissingRules.ValidateRunCount.ShouldBe(0);
            OnValidationFailHeaderMissingRules.FailRunCount.ShouldBe(1);
        }

        [TestMethod]
        public void Should_OnFailShouldNotBeInvokesWhenHeaderIsMissingAndHeaderIsNotRequired_AndSucceed()
        {
            var result = _provider.Validate<OnValidationFailHeaderMissingAndNotRequiredRules>(_encodedToken, _secret);

            result.ShouldBe(TokenValidationResult.Passed);
            OnValidationFailHeaderMissingAndNotRequiredRules.FailRunCount.ShouldBe(0);
            OnValidationFailHeaderMissingAndNotRequiredRules.ValidateRunCount.ShouldBe(0);
        }

        [TestMethod]
        public void Should_OnFailShouldCallOnValidationFailWhenItsInInheritedClass_AndSucceed()
        {
            var result = _provider.Validate<OnValidationFailShouldInherit>(_encodedToken, _secret);

            result.ShouldBe(TokenValidationResult.CustomCheckFailed);
            OnValidationFailShouldInheritFromAbstract.FailRunCount.ShouldBe(1);
            OnValidationFailShouldInherit.ValidateRunCount.ShouldBe(1);
        }
    }

    public class OnValidationFailRules
    {
        public static int ValidateRunCount { get; set; }
        public static int FailRunCount { get; set; }

        [Required]
        [VerifyClaim("tst")]
        public virtual TokenValidationResult Validate(long claimValue)
        {
            ValidateRunCount++;
            return claimValue == 1 ? TokenValidationResult.ClaimMissing : TokenValidationResult.Passed;
        }

        [OnValidationFail]
        public virtual void Fail(TokenValidationResult result, string claimKey, object claimValue)
        {
            FailRunCount++;
        }
    }

    public class OnValidationFailClaimMissingRules
    {
        public static int ValidateRunCount { get; set; }
        public static int FailRunCount { get; set; }

        [Required]
        [VerifyClaim("aaa")]
        public virtual TokenValidationResult Validate(long claimValue)
        {
            ValidateRunCount++;
            return claimValue == 1 ? TokenValidationResult.ClaimMissing : TokenValidationResult.Passed;
        }

        [OnValidationFail]
        public virtual void Fail(TokenValidationResult result, string claimKey, object claimValue)
        {
            FailRunCount++;
        }
    }

    public class OnValidationFailClaimMissingAndNotRequiredRules
    {
        public static int ValidateRunCount { get; set; }
        public static int FailRunCount { get; set; }

        [VerifyClaim("aaa")]
        public virtual TokenValidationResult Validate(long claimValue)
        {
            ValidateRunCount++;
            return claimValue == 1 ? TokenValidationResult.ClaimMissing : TokenValidationResult.Passed;
        }

        [OnValidationFail]
        public virtual void Fail(TokenValidationResult result, string claimKey, object claimValue)
        {
            FailRunCount++;
        }
    }

    public class OnValidationFailHeaderMissingRules
    {
        public static int ValidateRunCount { get; set; }
        public static int FailRunCount { get; set; }

        [Required]
        [VerifyHeader("aaa")]
        public virtual TokenValidationResult Validate(long claimValue)
        {
            ValidateRunCount++;
            return claimValue == 1 ? TokenValidationResult.ClaimMissing : TokenValidationResult.Passed;
        }

        [OnValidationFail]
        public virtual void Fail(TokenValidationResult result, string claimKey, object claimValue)
        {
            FailRunCount++;
        }
    }

    public class OnValidationFailHeaderMissingAndNotRequiredRules
    {
        public static int ValidateRunCount { get; set; }
        public static int FailRunCount { get; set; }

        [VerifyClaim("aaa")]
        public virtual TokenValidationResult Validate(long claimValue)
        {
            ValidateRunCount++;
            return claimValue == 1 ? TokenValidationResult.ClaimMissing : TokenValidationResult.Passed;
        }

        [OnValidationFail]
        public virtual void Fail(TokenValidationResult result, string claimKey, object claimValue)
        {
            FailRunCount++;
        }
    }

    public class OnValidationFailShouldInherit : OnValidationFailShouldInheritFromAbstract
    {
        public static int ValidateRunCount { get; set; }

        [VerifyClaim("tst")]
        public virtual TokenValidationResult Validate(long claimValue)
        {
            ValidateRunCount++;
            return claimValue == 2L ? TokenValidationResult.Passed : TokenValidationResult.CustomCheckFailed;
        }
    }

    public abstract class OnValidationFailShouldInheritFromAbstract
    {
        public static int FailRunCount { get; set; }

        [OnValidationFail]
        public virtual void Fail(TokenValidationResult result, string claimKey, object claimValue)
        {
            FailRunCount++;
        }
    }
}
