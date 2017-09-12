using Microsoft.VisualStudio.TestTools.UnitTesting;
using Shouldly;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Jot.Tests
{
    [TestClass]
    public class JotTokenTests
    {
        private IJotToken _token;

        [TestInitialize]
        public void TestInitialize()
        {
            var provider = new JotProvider(30, HashAlgorithm.HS256);

            var claims = new Dictionary<string, object>
            {
                { "iss", "me" }
            };

            _token = provider.Create(claims);
        }

        [TestMethod]
        public void Should_SetClaimOnToken_AndSucceed()
        {
            _token.SetClaim("clm", "cool");

            var result = _token.GetClaim<string>("clm");

            result.ShouldBe("cool");
        }

        [TestMethod]
        public void Should_GetNullClaimOnToken_AndSucceed()
        {
            _token.SetClaim("clm", null);

            var result = _token.GetClaim<string>("clm");

            result.ShouldBe(null);
        }

        [TestMethod]
        public void Should_GetFailWhenGettingNullClaimAndConvertedTypeIsNotNullable_AndSucceed()
        {
            try
            {
                _token.SetClaim("clm", null);

                var result = _token.GetClaim<int>("clm");
            }
            catch (Exception ex)
            {
                ex.Message.ShouldBe("Cannot convert null value.  Key: clm");
            }
        }

        [TestMethod]
        public void Should_GetFailWhenGettingNullClaimAndConvertedTypeIsNullable_AndSucceed()
        {
            _token.SetClaim("clm", null);

            var result = _token.GetClaim<int?>("clm");

            result.ShouldBe(null);
        }

        [TestMethod]
        public void Should_SetHeaderOnToken_AndSucceed()
        {
            _token.SetHeader("clm", "cool");

            var result = _token.GetHeader<string>("clm");

            result.ShouldBe("cool");
        }

        [TestMethod]
        public void Should_GetNullHeaderOnToken_AndSucceed()
        {
            _token.SetHeader("clm", null);

            var result = _token.GetHeader<string>("clm");

            result.ShouldBe(null);
        }

        [TestMethod]
        public void Should_GetFailWhenGettingNullHeaderAndConvertedTypeIsNotNullable_AndSucceed()
        {
            try
            {
                _token.SetHeader("clm", null);

                var result = _token.GetHeader<int>("clm");
            }
            catch (Exception ex)
            {
                ex.Message.ShouldBe("Cannot convert null value.  Key: clm");
            }
        }

        [TestMethod]
        public void Should_GetFailWhenGettingNullHeaderAndConvertedTypeIsNullable_AndSucceed()
        {
            _token.SetHeader("clm", null);

            var result = _token.GetHeader<int?>("clm");

            result.ShouldBe(null);
        }

        [TestMethod]
        public void Should_ReturnFalseWhenThereIsNoClaimForTryGetClaim_AndSucceed()
        {
            _token.SetClaim("clm", null);
            object value;

            var result = _token.TryGetClaim("aaa", out value);

            result.ShouldBe(false);
        }

        [TestMethod]
        public void Should_ReturnFalseWhenThereIsAClaimForTryGetClaim_AndSucceed()
        {
            _token.SetClaim("clm", "test");
            object value;

            var result = _token.TryGetClaim("clm", out value);

            result.ShouldBe(true);
            value.ShouldBe("test");
        }

        [TestMethod]
        public void Should_ReturnFalseWhenThereIsNoHeaderForTryGetHeader_AndSucceed()
        {
            _token.SetHeader("clm", null);
            object value;

            var result = _token.TryGetHeader("aaa", out value);

            result.ShouldBe(false);
        }

        [TestMethod]
        public void Should_ReturnFalseWhenThereIsAHeaderForTryGetHeader_AndSucceed()
        {
            _token.SetHeader("clm", "test");
            object value;

            var result = _token.TryGetHeader("clm", out value);

            result.ShouldBe(true);
            value.ShouldBe("test");
        }

        [TestMethod]
        public void Should_FindAClaimWhenItExists()
        {
            _token.SetClaim("clm", "test");

            var result = _token.ClaimExists("clm");

            result.ShouldBe(true);
        }

        [TestMethod]
        public void Should_NotFindAClaimWhenItExists()
        {
            _token.SetClaim("clm", "test");

            var result = _token.ClaimExists("aaa");

            result.ShouldBe(false);
        }

        [TestMethod]
        public void Should_FindAHeaderWhenItExists()
        {
            _token.SetHeader("clm", "test");

            var result = _token.HeaderExists("clm");

            result.ShouldBe(true);
        }

        [TestMethod]
        public void Should_NotFindAHeaderWhenItExists()
        {
            _token.SetHeader("clm", "test");

            var result = _token.HeaderExists("aaa");

            result.ShouldBe(false);
        }
    }
}
