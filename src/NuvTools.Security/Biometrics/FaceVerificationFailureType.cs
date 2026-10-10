namespace NuvTools.Security.Biometrics;

/// <summary>Why a captured face was not accepted.</summary>
/// <remarks>
/// The values tell the application which message helps the person: capturing again fixes
/// <see cref="FaceNotDetected"/>, <see cref="LowImageQuality"/> and <see cref="MultipleFaces"/>, but
/// never <see cref="FaceNotOnRecord"/>.
/// </remarks>
public enum FaceVerificationFailureType
{
    /// <summary>The capture was accepted.</summary>
    None = 0,

    /// <summary>The faces were compared and are not alike enough.</summary>
    NotMatched = 1,

    /// <summary>The provider did not accept the capture as being of a live person.</summary>
    LivenessRejected = 2,

    /// <summary>The document is not a valid CPF. The provider was not called.</summary>
    InvalidDocument = 3,

    /// <summary>The provider holds no face for this person, so no capture can ever match.</summary>
    FaceNotOnRecord = 4,

    /// <summary>No face could be recognised in the image.</summary>
    FaceNotDetected = 5,

    /// <summary>The image is too blurred, dark or small to compare.</summary>
    LowImageQuality = 6,

    /// <summary>More than one face was recognised in the image.</summary>
    MultipleFaces = 7,

    /// <summary>The image is empty, corrupted, too large or in a format the provider refuses.</summary>
    InvalidImage = 8,

    /// <summary>The provider refused the request for a reason this contract does not name.</summary>
    Rejected = 9,

    /// <summary>
    /// The provider could not be reached or answered unexpectedly. Nothing is known about the capture.
    /// </summary>
    Unavailable = 10
}
