namespace NuvTools.Security.Certificate;

/// <summary>Who a validated certificate was issued to.</summary>
/// <remarks>
/// Every value comes from the certificate itself. Which of them an application requires is its own
/// decision: a certificate issued to a company carries a CNPJ and the CPF of the person responsible,
/// one issued to a person may carry no CNPJ, and one from outside ICP-Brasil carries neither.
/// </remarks>
/// <param name="Name">Common name of the subject.</param>
/// <param name="Email">E-mail address in the certificate, when present.</param>
/// <param name="Cpf">CPF of the holder, digits only, when the certificate is an ICP-Brasil one.</param>
/// <param name="Cnpj">CNPJ of the company, digits only, when the certificate was issued to one.</param>
/// <param name="CompanyName">Name of the company, when the certificate was issued to one.</param>
public sealed record CertificateSubject(string? Name, string? Email, string? Cpf, string? Cnpj, string? CompanyName);
