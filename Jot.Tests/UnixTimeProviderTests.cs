using System;
using FakeItEasy;
using Jot.Time;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Shouldly;

namespace Jot.Tests
{
    [TestClass]
    public class UnixTimeProviderTests
    {
        [TestMethod]
        public void GetUnixTimestamp_ReturnsEquivalentUtcNow()
        {
            // Arrange
            var sut = new UnixTimeProvider();

            // Act
            var utcNow = DateTime.UtcNow;
            var generatedTimeStamp = sut.GetUnixTimestamp(0);

            // Assert
            var ticksDifference = utcNow.Ticks - new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero).Ticks;
            var expected = ticksDifference / TimeSpan.TicksPerSecond;

            generatedTimeStamp.ShouldBeGreaterThanOrEqualTo(expected);
            utcNow.ShouldBeGreaterThanOrEqualTo(new EpochConverter().ConvertToDateTime(expected));
        }

        [TestMethod]
        public void GetUnixTimestamp_ProviderInjected_GivesGoodEpochResult()
        {
            // Arrange
            var timeProvider = A.Fake<ITimeProvider>();
            var utcNow = new DateTime(2017, 1, 10, 16, 13, 2);
            A.CallTo(() => timeProvider.UtcNow).Returns(utcNow);

            var sut = new UnixTimeProvider(timeProvider);

            // Act
            var generatedTimeStamp = sut.GetUnixTimestamp(0);

            // Assert
            var ticksDifference = utcNow.Ticks - new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero).Ticks;
            var expected = ticksDifference / TimeSpan.TicksPerSecond;

            generatedTimeStamp.ShouldBe(expected);
            expected.ShouldBe(1484064782);

            var convertedDateTime = new EpochConverter().ConvertToDateTime(expected);
            utcNow.ShouldBe(convertedDateTime);
        }

        public class EpochConverter
        {
            public DateTime ConvertToDateTime(long secondsSinceEpoch)
            {
                var timeInTicks = secondsSinceEpoch * TimeSpan.TicksPerSecond;

                return new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc).AddTicks(timeInTicks);
            }
        }
    }
}