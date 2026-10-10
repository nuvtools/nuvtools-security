namespace NuvTools.Security.Biometrics;

/// <summary>
/// Verifies that a captured face belongs to the holder of a document, against the provider's record.
/// </summary>
/// <remarks>
/// Call it inside the sign-in operation itself, with the image the client just captured, and decide
/// on its result. A client must never be able to state that a verification already happened: an
/// endpoint that only verifies, followed by a sign-in that trusts the caller, verifies nothing.
/// </remarks>
public interface IFaceVerifier
{
    /// <summary>
    /// Compares the captured face with the one on record.
    /// </summary>
    /// <param name="request">Whose face it should be, and the capture.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>
    /// The verification result. An invalid document, an unusable image or a communication failure
    /// yields <see cref="FaceVerification.Matched"/> = <c>false</c> (fail-closed).
    /// </returns>
    Task<FaceVerification> VerifyAsync(FaceVerificationRequest request, CancellationToken cancellationToken = default);
}
