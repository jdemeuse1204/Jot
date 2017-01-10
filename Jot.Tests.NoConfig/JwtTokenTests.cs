using Microsoft.VisualStudio.TestTools.UnitTesting;
using Shouldly;

namespace Jot.Tests.NoConfig
{
    [TestClass]
    public class JwtTokenTests
    {
        [TestMethod]
        public void Create_NoTimeout_IssuedAtNotBeforeEqualsExpiration()
        {
            // Act
            var sut = new JwtTokenProvider.JwtToken(0);

            // Assert
            Assert.IsNotNull(sut);

            var issuedAt = sut.GetClaim<int>("iat");
            var expires = sut.GetClaim<int>("exp");
            var notBefore = sut.GetClaim<int>("nbf");

            issuedAt.ShouldNotBe(0);
            issuedAt.ShouldBe(notBefore);
            expires.ShouldBe(issuedAt);
        }

        [TestMethod]
        public void Create_WithTimeout_IssuedAtNotBeforeEqualsAndLessThanExpiration()
        {
            // Act
            var sut = new JwtTokenProvider.JwtToken(10);

            // Assert
            Assert.IsNotNull(sut);

            var issuedAt = sut.GetClaim<int>("iat");
            var expires = sut.GetClaim<int>("exp");
            var notBefore = sut.GetClaim<int>("nbf");

            issuedAt.ShouldNotBe(0);
            issuedAt.ShouldBe(notBefore);

            expires.ShouldBeGreaterThan(issuedAt);
        }
    }
}