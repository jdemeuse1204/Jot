using Jot.Rules;
using Jot.Time;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Shouldly;
using System.Threading;

namespace Jot.Tests.Rules
{
    [TestClass]
    public class RfcSpecRulesTests
    {
        private RfcSpecRules _rules;
        private UnixTimeProvider _time;

        [TestInitialize]
        public void TestInitialize()
        {
            _rules = new RfcSpecRules();
            _time = new UnixTimeProvider();
        }

        [TestMethod]
        public void Should_ValidateNfbClaim_AndPass()
        {
            var time = _time.GetUnixTimestamp();

            Thread.Sleep(1000);

            var result = _rules.ValidateNbfClaim(time);

            result.ShouldBe(TokenValidationResult.Passed);
        }

        [TestMethod]
        public void Should_ValidateNfbClaim_AndFail()
        {
            var time = _time.GetUnixTimestamp(60);

            var result = _rules.ValidateNbfClaim(time);

            result.ShouldBe(TokenValidationResult.NotBeforeFailed);
        }

        [TestMethod]
        public void Should_ValidateNfbClaim_WhenNbfIsNull_AndFail()
        {
            var result = _rules.ValidateNbfClaim(null);

            result.ShouldBe(TokenValidationResult.NotBeforeFailed);
        }

        [TestMethod]
        public void Should_ValidateExpClaim_AndPass()
        {
            var time = _time.GetUnixTimestamp(60);

            var result = _rules.ValidateExpClaim(time);

            result.ShouldBe(TokenValidationResult.Passed);
        }

        [TestMethod]
        public void Should_ValidateExpClaim_AndFail()
        {
            var time = _time.GetUnixTimestamp(-60);

            var result = _rules.ValidateExpClaim(time);

            result.ShouldBe(TokenValidationResult.TokenExpired);
        }

        [TestMethod]
        public void Should_ValidateExpClaim_WhenExpIsNull_AndFail()
        {
            var result = _rules.ValidateExpClaim(null);

            result.ShouldBe(TokenValidationResult.TokenExpired);
        }

        [TestMethod]
        public void Should_ValidateIatClaim_AndPass()
        {
            var result = _rules.ValidateIatClaim("0");

            result.ShouldBe(TokenValidationResult.Passed);
        }

        [TestMethod]
        public void Should_ValidateIatClaim_WhenIatIsNull_AndFail()
        {
            var result = _rules.ValidateIatClaim(null);

            result.ShouldBe(TokenValidationResult.CreatedTimeCheckFailed);
        }

        [TestMethod]
        public void Should_ValidateIatClaim_WhenIatIsEmpty_AndFail()
        {
            var result = _rules.ValidateIatClaim(null);

            result.ShouldBe(TokenValidationResult.CreatedTimeCheckFailed);
        }

        [TestMethod]
        public void Should_ValidateIatClaim_WhenIatIsNotNumeric_AndFail()
        {
            var result = _rules.ValidateIatClaim("test");

            result.ShouldBe(TokenValidationResult.CreatedTimeCheckFailed);
        }

        [TestMethod]
        public void Should_ValidateIatClaim_WhenIatIsAlphaNumeric_AndFail()
        {
            var result = _rules.ValidateIatClaim("10test");

            result.ShouldBe(TokenValidationResult.CreatedTimeCheckFailed);
        }
    }
}
