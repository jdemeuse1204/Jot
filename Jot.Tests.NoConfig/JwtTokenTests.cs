using FakeItEasy;
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

        [TestMethod]
        public void Create_NoTimeout_AllEpochTimeBasedOnProvider()
        {
            // Arrange
            var timeProvider = A.Fake<ITimeProvider>();
            var epochTimeProvided = 12000;
            A.CallTo(() => timeProvider.GetUnixTimestamp()).Returns(epochTimeProvided);
            A.CallTo(() => timeProvider.GetUnixTimestamp(0)).Returns(epochTimeProvided);

            // Act
            var sut = new JwtTokenProvider.JwtToken(timeProvider, 0);

            // Assert
            A.CallTo(() => timeProvider.GetUnixTimestamp()).MustHaveHappened(Repeated.Exactly.Twice);
            A.CallTo(() => timeProvider.GetUnixTimestamp(0)).MustHaveHappened(Repeated.Exactly.Once);
            Assert.IsNotNull(sut);

            var issuedAt = sut.GetClaim<int>("iat");
            var expires = sut.GetClaim<int>("exp");
            var notBefore = sut.GetClaim<int>("nbf");

            issuedAt.ShouldBe(epochTimeProvided);
            issuedAt.ShouldBe(notBefore);
            expires.ShouldBe(issuedAt);
        }
    }
}