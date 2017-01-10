namespace Jot.Time
{
    public interface IUnixTimeProvider
    {
        /// <summary>
        ///     Gets the unix timestamp (time since epoch) based on Universal Time.
        /// </summary>
        long GetUnixTimestamp();

        /// <summary>
        ///     Gets the unix timestamp (time since epoch) based on Universal Time.
        /// </summary>
        /// <param name="minutesToAdd">The minutes to add.</param>
        long GetUnixTimestamp(int minutesToAdd);
    }
}