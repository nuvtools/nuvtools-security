namespace NuvTools.Security.Certificate;

/// <summary>Result of validating a signed certificate challenge.</summary>
/// <param name="Valid">
/// Whether the provider confirmed possession of the private key and the certificate's trust chain.
/// </param>
/// <param name="Subject">Who the certificate was issued to. Set only when <paramref name="Valid"/> is <c>true</c>.</param>
/// <param name="Failure">Why the authentication failed, or <see cref="CertificateFailureType.None"/>.</param>
public sealed record CertificateAuthentication(bool Valid, CertificateSubject? Subject, CertificateFailureType Failure)
{
    /// <summary>Creates the result of an authentication the provider accepted.</summary>
    /// <param name="subject">Who the certificate was issued to.</param>
    public static CertificateAuthentication Succeeded(CertificateSubject subject)
        => new(true, subject, CertificateFailureType.None);

    /// <summary>Creates the result of an authentication that did not go through.</summary>
    /// <param name="failure">Why it failed.</param>
    public static CertificateAuthentication Failed(CertificateFailureType failure)
        => new(false, null, failure);
}
