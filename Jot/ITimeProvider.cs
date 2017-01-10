namespace Jot
{
    public interface ITimeProvider
    {
        /// <summary>
        /// Gets the unix timestamp (time since epoch) based on Universal Time.
        /// </summary>
        /// <returns></returns>
        long GetUnixTimestamp();

        /// <summary>
        /// Gets the unix timestamp (time since epoch) based on Universal Time.
        /// </summary>
        /// <param name="minutesToAdd">The minutes to add.</param>
        /// <returns></returns>
        long GetUnixTimestamp(int minutesToAdd);
    }
}