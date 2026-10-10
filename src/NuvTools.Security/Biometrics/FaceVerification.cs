namespace NuvTools.Security.Biometrics;

/// <summary>Result of comparing a captured face with the one on record.</summary>
/// <param name="Matched">
/// Whether the capture was accepted as the person: similarity at or above the configured minimum and,
/// when liveness is enforced, a liveness the application accepts.
/// </param>
/// <param name="Similarity">
/// How alike the two faces are (0.0 = different, 1.0 = identical). Zero when no comparison happened.
/// </param>
/// <param name="Liveness">
/// What the provider reported about the capture being of a live person, in its own words, or
/// <c>null</c> when it reported nothing.
/// </param>
/// <param name="Failure">Why the capture was not accepted, or <see cref="FaceVerificationFailureType.None"/>.</param>
public sealed record FaceVerification(bool Matched, double Similarity, string? Liveness, FaceVerificationFailureType Failure)
{
    /// <summary>Creates the result of a verification that never reached a comparison.</summary>
    /// <param name="failure">Why it failed.</param>
    public static FaceVerification Failed(FaceVerificationFailureType failure)
        => new(false, 0, null, failure);
}
