namespace NuvTools.Security.Signing.Azure;

/// <summary>
/// Decides which version signs and in what order the versions are offered.
/// </summary>
internal static class SigningKeyOrder
{
    /// <summary>
    /// Arranges the versions so the first is the one to sign with.
    /// </summary>
    /// <param name="versions">The usable versions, in any order.</param>
    /// <param name="now">The current time.</param>
    /// <param name="activationDelay">How long a version is published before it signs.</param>
    /// <returns>
    /// The newest version that has been published for at least <paramref name="activationDelay"/>,
    /// followed by the others from newest to oldest. When none is old enough — a key that was only
    /// just created — the oldest signs, being the one validators have known longest.
    /// </returns>
    public static IReadOnlyList<SigningKeyVersion> Arrange(
        IEnumerable<SigningKeyVersion> versions, DateTimeOffset now, TimeSpan activationDelay)
    {
        var newestFirst = versions.OrderByDescending(version => version.CreatedOn).ToList();

        if (newestFirst.Count == 0)
            return newestFirst;

        var signing = newestFirst.FirstOrDefault(version => version.CreatedOn <= now - activationDelay)
                      ?? newestFirst[^1];

        return [signing, .. newestFirst.Where(version => version != signing)];
    }
}
