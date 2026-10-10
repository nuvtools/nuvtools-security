namespace NuvTools.Security.Certificate;

/// <summary>Why a certificate authentication did not go through.</summary>
public enum CertificateFailureType
{
    /// <summary>The authentication succeeded.</summary>
    None = 0,

    /// <summary>
    /// The provider answered and refused: no token, a signature that does not match, or a certificate
    /// that is expired, revoked or outside the trusted chain.
    /// </summary>
    Rejected = 1,

    /// <summary>
    /// The provider could not be reached or answered unexpectedly, which includes a token it no
    /// longer knows. Nothing is known about the certificate.
    /// </summary>
    Unavailable = 2
}
