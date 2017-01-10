using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Linq;
using Shouldly;
using FakeItEasy;
using Jot.Time;

namespace Jot.Tests.NoConfig
{
    [TestClass]
    public class JotTestsNoConfig
    {
        [TestMethod]
        public void CreateClaimWithNoPayload()
        {
            var jot = new JotProvider(30, HashAlgorithm.HS512);

            var token = jot.Create();

            Assert.IsNotNull(token);
        }

        [TestMethod]
        public void CreateClaimWithPayload()
        {
            var jot = new JotProvider(30, HashAlgorithm.HS512);

            var payload = new Dictionary<string, object>
            {
                    {"iat", ""},
                    {"exp", ""},
                    {"rol", ""},
                    {"jti", ""},
                    {"iss", ""},
                    {"aud", ""},
                    {"nbf", ""},
                    {"sub", ""},
                    {"usr", ""}
            };

            var token = jot.Create(payload);

            Assert.IsNotNull(token);
        }

        [TestMethod]
        public void CheckDefaultCreationValues()
        {
            var jot = new JotProvider(30, HashAlgorithm.HS512);

            var token = jot.Create();

            var exp = token.GetClaim<double>("exp");
            var iat = token.GetClaim<double>("iat");
            var jti = token.GetClaim<Guid>("jti");
            var nbf = token.GetClaim<double>("nbf");

            iat.ShouldBeGreaterThan(0);
            nbf.ShouldBeGreaterThan(0);
            exp.ShouldBeGreaterThan(0);
            jti.ShouldNotBe(Guid.Empty);
        }

        [TestMethod]
        public void CreateClaimWithPayloadAndMakeSureValuesAreSet()
        {
            var jot = new JotProvider(30, HashAlgorithm.HS512);

            var payload = new Dictionary<string, object>
            {
                    {"iat", ""},
                    {"exp", ""},
                    {"rol", "Test"},
                    {"jti", Guid.Empty},
                    {"iss", "Test"},
                    {"aud", ""},
                    {"nbf", ""},
                    {"sub", ""},
                    {"usr", ""}
            };

            var token = jot.Create(payload);

            var rol = token.GetClaim<string>("rol");
            var jti = token.GetClaim<Guid>("jti");
            var iss = token.GetClaim<string>("iss");

            Assert.IsTrue(string.Equals(rol, "Test") && string.Equals(iss, "Test") && jti == Guid.Empty);
        }

        [TestMethod]
        public void MakeSureClaimIsEncryptedCorrectly()
        {
            var jot = new JotProvider(30, HashAlgorithm.HS512);

            jot.OnCreate += (jwt) =>
            {
                jwt.SetClaim("iss", "IssuedByMe!");
            };

            var token = jot.Create();

            var encodedToken = jot.Encode(token, "kjsdkfjgosdjfgoi");

            Assert.IsTrue(encodedToken.Split('.').Count() == 3);
        }


        [TestMethod]
        public void Create_NoTimeout_IssuedAtNotBeforeEqualsExpiration()
        {
            // Act
            var provider = new JotProvider(0, HashAlgorithm.HS256);

            var sut = provider.Create();

            // Assert
            Assert.IsNotNull(sut);

            var issuedAt = sut.GetClaim<long>("iat");
            var expires = sut.GetClaim<long>("exp");
            var notBefore = sut.GetClaim<long>("nbf");

            issuedAt.ShouldNotBe(0);
            issuedAt.ShouldBe(notBefore);
            expires.ShouldBe(issuedAt);
        }

        [TestMethod]
        public void Create_WithTimeout_IssuedAtNotBeforeEqualsAndLessThanExpiration()
        {
            // Act
            var provider = new JotProvider(10, HashAlgorithm.HS256);

            var sut = provider.Create();

            // Assert
            Assert.IsNotNull(sut);

            var issuedAt = sut.GetClaim<long>("iat");
            var expires = sut.GetClaim<long>("exp");
            var notBefore = sut.GetClaim<long>("nbf");

            issuedAt.ShouldNotBe(0);
            issuedAt.ShouldBe(notBefore);

            expires.ShouldBeGreaterThan(issuedAt);
        }

        [TestMethod]
        public void Create_NoTimeout_AllEpochTimeBasedOnProvider()
        {
            // Arrange
            var timeProvider = A.Fake<IUnixTimeProvider>();
            var epochTimeProvided = 12000;
            A.CallTo(() => timeProvider.GetUnixTimestamp()).Returns(epochTimeProvided);
            A.CallTo(() => timeProvider.GetUnixTimestamp(0)).Returns(epochTimeProvided);

            // Act
            var provider = new JotProvider(timeProvider, 0, HashAlgorithm.HS256);

            var sut = provider.Create();

            // Assert
            A.CallTo(() => timeProvider.GetUnixTimestamp()).MustHaveHappened(Repeated.Exactly.Twice);
            A.CallTo(() => timeProvider.GetUnixTimestamp(0)).MustHaveHappened(Repeated.Exactly.Once);
            Assert.IsNotNull(sut);

            var issuedAt = sut.GetClaim<long>("iat");
            var expires = sut.GetClaim<long>("exp");
            var notBefore = sut.GetClaim<long>("nbf");

            issuedAt.ShouldBe(epochTimeProvided);
            issuedAt.ShouldBe(notBefore);
            expires.ShouldBe(issuedAt);
        }
    }
}
