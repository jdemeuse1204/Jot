using Jot.Attributes;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Shouldly;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Jot.Tests.Attributes
{
    [TestClass]
    public class InjectFromPayloadTests
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
            var result = _provider.Validate<TestInjectFromPayloadRules>(_encodedToken, _secret, new { aaa = 1 });

            result.ShouldBe(TokenValidationResult.Passed);
        }

        [TestMethod]
        public void Should_ValidateClaimWithInjectableClaimAndFailWhenPayloadIsNull_AndFail()
        {
            try
            {
                _provider.Validate<TestInjectFromPayloadRules>(_encodedToken, _secret);
            }
            catch (Exception ex)
            {
                ex.Message.ShouldBe("Payload is null, cannot find properties on a null payload.");
            }
        }

        [TestMethod]
        public void Should_ValidateClaimWithInjectableClaimAndFailWhenItIsMissing_AndFail()
        {
            try
            {
                _provider.Validate<TestInjectFromPayloadRules>(_encodedToken, _secret, new { bbb = 1 });
            }
            catch (Exception ex)
            {
                ex.Message.ShouldBe("Payload is missing property.  Property Name: aaa");
            }
        }


        [TestMethod]
        public void Should_ValidateClaimWithInjectableClaimAndFailWithConversionError_AndFail()
        {
            try
            {
                _provider.Validate<TestInjectFromPayloadRules>(_encodedToken, _secret, new { aaa = "aaa" });
            }
            catch (Exception ex)
            {
                ex.Message.ShouldBe($"Cannot convert Payload property aaa from {typeof(string).Name} to {typeof(int).Name}.  Payload Property Name: aaa");
            }
        }
    }

    public class TestInjectFromPayloadRules
    {
        [VerifyClaim("iss")]
        public virtual TokenValidationResult Validate(string claimValue, [InjectFromPayload("aaa")] int value)
        {
            return value == 1 ? TokenValidationResult.Passed : TokenValidationResult.CustomCheckFailed;
        }
    }
}
