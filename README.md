# NuvTools Security Libraries

[![NuGet](https://img.shields.io/nuget/v/NuvTools.Security.svg)](https://www.nuget.org/packages/NuvTools.Security/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A suite of .NET libraries for implementing security features in ASP.NET Core and Blazor applications, including JWT authentication, cryptography, claims-based authorization, and authentication state management. These libraries target modern .NET platforms, including .NET 8, .NET 9, and .NET 10.

## Libraries

### NuvTools.Security

Core security library providing JWT token handling, cryptography utilities, claims extensions, and authorization policy builders.

**Key Features:**
- **JWT Helper**: Generate, parse, validate JWT tokens and refresh tokens
- **Cryptography Helper**: SHA256 and SHA512 hashing utilities
- **ClaimsPrincipal Extensions**: Easy extraction of user information from claims with multiple fallback sources
- **Claim Extensions**: Build claims collections with permission support
- **Authorization Extensions**: Fluent API for building permission-based policies
- **CAPTCHA Contract**: Options, header constants and the `ICaptchaVerifier` abstraction shared by client and server
- **Certificate and Biometrics Contracts**: `ICertificateAuthenticator`, `IDocumentSigner` and `IFaceVerifier`, provider-neutral, with their result and failure types
- **SSRF protection**: `NetworkAddressPolicy` and `PublicNetworkConnector` restrict outbound HTTP connections to publicly routable addresses, judged on the address the socket actually connects to

> Carries no ASP.NET Core framework reference, so it is safe to consume from Blazor WebAssembly.

### NuvTools.Security.AspNetCore

Security configuration, authenticated user services and adaptive CAPTCHA verification for ASP.NET Core applications.

**Key Features:**
- **Security Configuration**: JWT configuration model (Issuer, Audience, SecretKey) with IOptions pattern
- **Current User Service**: Access current authenticated user and connection details via dependency injection
- **Adaptive CAPTCHA Filter**: `[ValidateCaptcha]` gates public endpoints — invisible score check by default, escalating to a checkbox challenge when the risk is high
- **reCAPTCHA Enterprise Verifier**: creates the assessment on Google Cloud; the API key never leaves the server

> Requires the ASP.NET Core shared framework. Do **not** reference it from a WebAssembly project — use `NuvTools.Security` for the shared contract instead.

### NuvTools.Security.AspNetCore.Blazor

Authentication state providers for Blazor applications with JWT and OIDC support, plus the client half of the adaptive CAPTCHA.

**Key Features:**
- **Manual Authentication State Provider**: JWT-based auth with local storage and automatic token expiration handling
- **OIDC Authentication State Provider**: OpenID Connect authentication integration
- **NuvCaptcha Component**: Invisible by default, rendering the "I'm not a robot" checkbox only on step-up

### NuvTools.Security.Certificate.Lacuna

Lacuna REST PKI behind the `ICertificateAuthenticator` and `IDocumentSigner` contracts that `NuvTools.Security` defines.

**Key Features:**
- **Validated on the service**: possession of the private key and the ICP-Brasil chain are checked by REST PKI — no key or licence is kept locally
- **Fail-closed**: a missing token, a refused certificate or an unreachable provider never yields an identity
- **PDF signing (PAdES)**: prepares the document, places the visible stamp and completes the signature, with the key kept by the person

### NuvTools.Security.Biometrics.Serpro

SERPRO Datavalid behind the `IFaceVerifier` contract that `NuvTools.Security` defines.

**Key Features:**
- **Government record**: the capture is matched against the face on record for a CPF, with a cached gateway token
- **The application decides**: minimum similarity and accepted liveness values are configuration, not code

> The contracts live in `NuvTools.Security`; each provider is a package of its own. An application depends on `ICertificateAuthenticator` and `IFaceVerifier`, names the provider once at registration, and changes provider by changing that one call.

## Installation

Install via NuGet Package Manager:

```bash
# For core security features (JWT, cryptography, claims)
dotnet add package NuvTools.Security

# For ASP.NET Core integration (includes NuvTools.Security)
dotnet add package NuvTools.Security.AspNetCore

# For Blazor authentication state providers
dotnet add package NuvTools.Security.AspNetCore.Blazor

# For sign-in with a digital certificate, through Lacuna REST PKI (includes NuvTools.Security)
dotnet add package NuvTools.Security.Certificate.Lacuna

# For facial verification, through SERPRO Datavalid (includes NuvTools.Security)
dotnet add package NuvTools.Security.Biometrics.Serpro
```

Or via Package Manager Console:

```powershell
Install-Package NuvTools.Security
Install-Package NuvTools.Security.AspNetCore
Install-Package NuvTools.Security.AspNetCore.Blazor
```

## Quick Start

### JWT Token Generation and Validation

```csharp
using NuvTools.Security.Helpers;
using System.Security.Claims;

// Generate a JWT token
var claims = new List<Claim>
{
    new Claim(ClaimTypes.NameIdentifier, "user123"),
    new Claim(ClaimTypes.Email, "user@example.com"),
    new Claim(ClaimTypes.Role, "Admin")
};

string token = JwtHelper.Generate(
    key: "your-secret-key-at-least-32-characters",
    issuer: "your-app",
    audience: "your-app-users",
    claims: claims,
    expires: DateTime.UtcNow.AddHours(1)
);

// Parse claims from JWT (client-side, no validation)
var parsedClaims = JwtHelper.ParseClaimsFromJwt(token);

// Check if token is expired
bool isExpired = JwtHelper.IsTokenExpired(token);

// Generate a refresh token
string refreshToken = JwtHelper.GenerateRefreshToken();

// Extract principal from expired token (for refresh flow)
var principal = JwtHelper.GetPrincipalFromExpiredToken(token, "your-secret-key");
```

### Cryptography and Hashing

```csharp
using NuvTools.Security.Helpers;

// Compute SHA256 hash
string hash256 = HashHelper.ComputeSHA256Hash("sensitive-data");

// Compute SHA512 hash
string hash512 = HashHelper.ComputeSHA512Hash("sensitive-data");

// Generic method with algorithm selection
string hash = HashHelper.ComputeHash(
    "data",
    HashHelper.HashAlgorithmType.SHA512
);
```

### AES Symmetric Encryption

```csharp
using NuvTools.Security.Helpers;

// Encrypt to a Base64 string (format: IV (16 bytes) + ciphertext, SHA-256-derived key)
string cipher = AesEncryptionHelper.EncryptToString("sensitive-data", "your-secret-key");

// Decrypt back to plain text (non-Base64 input is returned as-is for legacy data)
string plain = AesEncryptionHelper.DecryptToString(cipher, "your-secret-key");

// Choose the AES key size explicitly
string cipher128 = AesEncryptionHelper.EncryptToString(
    "data",
    "your-secret-key",
    AesEncryptionHelper.SymmetricAlgorithmType.AES128
);
```

### Claims Principal Extensions

```csharp
using NuvTools.Security.Extensions;

// In a controller or service
public class UserController : ControllerBase
{
    public IActionResult GetProfile()
    {
        // Extract user information with automatic fallback
        var userId = User.GetId();           // NameIdentifier or Sub
        var email = User.GetEmail();         // Email, upn, preferred_username, etc.
        var name = User.GetName();
        var givenName = User.GetGivenName();
        var familyName = User.GetFamilyName();

        // Get custom extension attributes (Azure AD B2C)
        var roles = User.GetCustomAttributeValues<string>("roles");
        var permissions = User.GetCustomAttributeValues<int>("permissionIds");

        // Check for specific custom attribute value
        bool hasPermission = User.HasValue("permissions", "users.write");

        return Ok(new { userId, email, name });
    }
}
```

### Building Claims Collections

```csharp
using NuvTools.Security.Extensions;

// Add individual permissions
var claims = new List<Claim>();
claims.AddPermission("users.read");
claims.AddPermission("users.write");

// Add all permissions from a static class
public static class UserPermissions
{
    public const string Read = "users.read";
    public const string Write = "users.write";
    public const string Delete = "users.delete";
}

claims.AddPermissionByClass(typeof(UserPermissions));

// Add claims from a class with custom claim type
claims.AddByClass("custom-claim-type", typeof(MyClaimsClass));
```

### Authorization Policies with Permissions

```csharp
using NuvTools.Security.Extensions;

builder.Services.AddAuthorization(options =>
{
    // Add policy requiring specific permission claim
    options.AddPolicyWithRequiredPermissionClaim(
        "CanManageUsers",
        "users.write", "users.delete");

    // Add policy with custom claim type and values
    options.AddPolicyWithRequiredClaim(
        "AdminOnly",
        "role",
        "Admin", "SuperAdmin");

    // Add policy with multiple different claims
    options.AddPolicyWithRequiredClaim(
        "ComplexPolicy",
        new Claim(NuvTools.Security.Models.ClaimTypes.Permission, "reports.read"),
        new Claim("department", "IT")
    );
});

// In controller
[Authorize(Policy = "CanManageUsers")]
public class UserManagementController : ControllerBase
{
    [HttpPost]
    public IActionResult CreateUser() { /* ... */ }
}
```

### ASP.NET Core Configuration

**appsettings.json:**
```json
{
  "NuvTools.Security": {
    "Issuer": "your-application",
    "Audience": "your-application-users",
    "SecretKey": "your-secret-key-min-32-chars-long"
  }
}
```

**Program.cs:**
```csharp
using NuvTools.Security.AspNetCore.Configurations;
using NuvTools.Security.AspNetCore.Services;

var builder = WebApplication.CreateBuilder(args);

// Register security configuration
builder.Services.AddSecurityConfiguration(builder.Configuration);

// Register CurrentUserService
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<CurrentUserService>();

var app = builder.Build();
```

**Using CurrentUserService:**
```csharp
public class MyService(CurrentUserService currentUser)
{
    public void DoSomething()
    {
        var userId = currentUser.NameIdentifier;
        var ipAddress = currentUser.RemoteIpAddress;
        var fullAddress = currentUser.FullRemoteAddress;
        var claims = currentUser.Claims;
    }
}
```

### Blazor Manual Authentication

**Program.cs:**
```csharp
using NuvTools.Security.AspNetCore.Blazor;
using NuvTools.AspNetCore.Blazor.Extensions;
using Microsoft.AspNetCore.Components.Authorization;

var builder = WebAssemblyHostBuilder.CreateDefault(args);

// Register local storage service (required by ManualAuthenticationStateProvider)
builder.Services.AddLocalStorageService();

// Register authentication
builder.Services.AddScoped<AuthenticationStateProvider, ManualAuthenticationStateProvider>();
builder.Services.AddAuthorizationCore();

await builder.Build().RunAsync();
```

**Login Component:**
```csharp
@inject AuthenticationStateProvider AuthStateProvider

private async Task LoginAsync(string token)
{
    var authProvider = (ManualAuthenticationStateProvider)AuthStateProvider;
    await authProvider.SignInAsync(token);

    // Navigate to protected page
    Navigation.NavigateTo("/dashboard");
}

private async Task LogoutAsync()
{
    var authProvider = (ManualAuthenticationStateProvider)AuthStateProvider;
    await authProvider.SignOutAsync();

    Navigation.NavigateTo("/");
}
```

### OIDC Authentication in Blazor

**Program.cs:**
```csharp
using NuvTools.Security.AspNetCore.Blazor;
using Microsoft.AspNetCore.Components.Authorization;

builder.Services.AddOidcAuthentication(options =>
{
    builder.Configuration.Bind("AzureAd", options.ProviderOptions);
});

// Use custom OIDC provider
builder.Services.AddScoped<AuthenticationStateProvider, OidcAuthenticationStateProvider>();
```

### Adaptive CAPTCHA

Protects public endpoints (login, password reset, public queries) from automated abuse. A **score** key runs invisibly on every submission; when the risk is high the client escalates to a **checkbox** challenge.

**Server** — `NuvTools.Security.AspNetCore`:

```csharp
// Program.cs
services.AddCaptcha(builder.Configuration);

// Controller
[HttpPost("forgotpassword")]
[ValidateCaptcha]
public async Task<IActionResult> ForgotPassword(ForgotPasswordModel model) { ... }
```

```json
{
  "Captcha": {
    "Enabled": true,
    "ProjectId": "my-gcp-project",
    "ApiKey": "<from-key-vault>",
    "ScoreSiteKey": "<score-key>",
    "SiteKey": "<checkbox-key>",
    "MinScore": 0.5,
    "FailureMessage": "Security verification failed. Reload the page and try again."
  }
}
```

**Client** — `NuvTools.Security.AspNetCore.Blazor`:

```csharp
// Program.cs — only the site keys are read here, never the API key
services.AddCaptcha(builder.Configuration);
```

```razor
@using NuvTools.Security.AspNetCore.Blazor.Captcha

<NuvCaptcha @ref="_captcha" />

@code {
    private NuvCaptcha _captcha = default!;

    private async Task SubmitAsync()
    {
        var (token, mode) = await _captcha.GetTokenAsync();

        // The checkbox is on screen but unsolved — stop and let the user solve it.
        if (mode == CaptchaDefaults.ModeCheckbox && string.IsNullOrEmpty(token))
            return;

        var request = new HttpRequestMessage(HttpMethod.Post, "v1/security/account/forgotpassword");
        request.AddCaptchaToken(token, mode);

        var result = await Send(request);

        // Low score: the server asked for the step-up, so render the checkbox and let the user retry.
        if (await _captcha.HandleStepUpAsync(result))
            return;

        if (!result.Succeeded)
            await _captcha.ResetAsync(); // the token is single-use
    }
}
```

Set `Captcha:Enabled` to `false` in development so no token is required. When the provider script cannot load, the client sends an empty token and the server rejects it — the user sees a message instead of a stuck button.

### Fetching URLs Somebody Else Supplied (SSRF)

When an application fetches a URL a user typed — a webhook, a health probe, a document to import — it can be pointed at its own network: `http://169.254.169.254/` (cloud metadata), `http://10.0.0.5/admin`, or a public domain whose DNS answers a private address. Checking the URL first does not help, because DNS can answer differently to the check and to the connection.

`PublicNetworkConnector` checks the address inside `SocketsHttpHandler.ConnectCallback` — the address that is checked is the address the socket connects to. Every hop goes through it, so a redirect to a private address is refused too, and the proxy is switched off so the callback never only sees a proxy.

```csharp
using NuvTools.Security.Network;

// Publicly routable addresses only
using var client = new HttpClient(PublicNetworkConnector.CreateHandler());

try
{
    var body = await client.GetStringAsync(userSuppliedUrl);
}
catch (HttpRequestException ex) when (ex.InnerException is NetworkAddressNotAllowedException refused)
{
    // refused.Host is safe to log; refused.Address is the address that was denied
}

// With IHttpClientFactory
services.AddHttpClient("untrusted")
    .ConfigurePrimaryHttpMessageHandler(() => PublicNetworkConnector.CreateHandler());

// A handler created elsewhere (a reverse proxy's forwarder, for example)
PublicNetworkConnector.Apply(socketsHttpHandler, new NetworkAddressPolicy(
    allowedNetworks: [IPNetwork.Parse("10.20.0.0/16")],          // an internal range you trust
    additionalDeniedHostSuffixes: ["azurecontainerapps.io"]));   // names refused before any lookup
```

Denied by default: loopback, private (RFC 1918, IPv6 unique-local), link-local including `169.254.169.254`, carrier-grade NAT, documentation and benchmarking ranges, multicast, reserved space, IPv6 prefixes that embed an IPv4 address (NAT64, 6to4, Teredo), Azure's platform address `168.63.129.16`, and the host names `localhost`, `*.localhost`, `*.local` and `*.internal`. An IPv4-mapped IPv6 address is judged as the IPv4 address it carries. A name resolving to *any* denied address is refused as a whole.

`NetworkAddressPolicy.ResolveAllowedAsync(host)` applies the same rule without making a request — useful for validating a host a user registers.

### Sign-in with a Digital Certificate

The server opens a challenge, the browser signs it with the certificate the person picks, and the server validates the answer. The identity comes from the certificate the provider validated — never from a value the client sends.

```json
{
  "RestPki": {
    "AccessToken": "<from the REST PKI console>",
    "SecurityContext": "PkiBrazil"
  }
}
```

```csharp
using NuvTools.Security.Certificate;                    // the contract, from NuvTools.Security
using NuvTools.Security.Certificate.Lacuna.Extensions;  // the provider — named here and nowhere else

builder.Services.AddLacunaCertificateAuthentication(builder.Configuration);

// 1. Hand the challenge to the client, which signs it with Web PKI (signWithRestPki)
var challenge = await authenticator.StartAsync(cancellationToken);

// 2. Inside the sign-in operation itself, validate what came back
var result = await authenticator.CompleteAsync(signedToken, cancellationToken);

if (!result.Valid)
    return Unauthorized();   // result.Failure says whether it was refused or the provider was out of reach

var user = await users.FindByCpfAsync(result.Subject!.Cpf);
```

`SecurityContext` chooses the roots a certificate must chain to: `PkiBrazil` (the default), `LacunaTest`, or the id of a security context from the REST PKI console. `LacunaTest` accepts certificates anyone can issue, so keep it to development; an unknown value stops the application instead of falling back.

`CertificateSubject` carries the name, e-mail, CPF, CNPJ and company name found in the certificate. Which of them a sign-in requires is the application's decision.

### Signing a PDF with a Digital Certificate

The same two steps as the sign-in, applied to a document: the server prepares the PDF and opens a challenge, the browser signs it with the certificate the person picks, and the server completes the signature. The private key never leaves the person's device.

```csharp
using NuvTools.Security.Certificate.Signing;            // the contract, from NuvTools.Security
using NuvTools.Security.Certificate.Lacuna.Extensions;  // the provider — named here and nowhere else

builder.Services.AddLacunaDocumentSigning(builder.Configuration);

// Who is about to sign, read from the certificate itself
var certificate = await signer.ReadCertificateAsync(certificateDer, cancellationToken);

// Who signed already, to refuse the same person twice
var previous = await signer.GetSignersAsync(pdf, cancellationToken);

// 1. Prepare the document; the client signs challenge.Token with Web PKI (signWithRestPki)
var stamp = new SignatureStamp(stampImage, "image/png",
    new SignatureStampPlacement(PageNumber: -1, new SignatureStampArea(1.4, 4.9, 1.4, 2.2), Width: 8, Height: 2.2, RowSpacing: 0.3));

var challenge = await signer.StartAsync(new DocumentSignatureRequest(pdf, stamp), cancellationToken);

// 2. Complete it, and check the certificate that was actually used
var signed = await signer.CompleteAsync(signedToken, cancellationToken);

if (signed.Signer.Subject.Cpf != certificate.Subject.Cpf)
    return Forbid();   // the client chooses the certificate at signing time
```

The stamp is optional and its image is the application's: the provider only places it. Stamps are stacked inside an area of a page, so a co-signature lands after the ones already there. Measures are in centimeters; a negative page number counts from the end.

`ReadCertificateAsync` and `GetSignersAsync` read without validating — they answer what a certificate says, not whether it is trusted. The chain is validated when the signature is completed, against the `SecurityContext` configured for REST PKI.

Unlike the sign-in, a provider failure here propagates as an exception: signing is not an access decision, so there is no safe result to fall back to.

The PDF is signed under the basic PAdES policy unless `RestPki:PadesSignaturePolicy` holds the id of another one.

### Facial Verification

The capture is compared with the face on record for the person, and the application decides what counts as a match.

```json
{
  "Datavalid": {
    "ConsumerKey": "<from the SERPRO contract>",
    "ConsumerSecret": "<from the SERPRO contract>",
    "MinSimilarity": 0.9,
    "AcceptedLiveness": []
  }
}
```

```csharp
using NuvTools.Security.Biometrics;                    // the contract, from NuvTools.Security
using NuvTools.Security.Biometrics.Serpro.Extensions;  // the provider — named here and nowhere else

builder.Services.AddSerproFaceVerification(builder.Configuration);

// Inside the sign-in operation itself, with the CPF of the account being signed in to
var result = await verifier.VerifyAsync(new FaceVerificationRequest(user.Cpf, imageBytes), cancellationToken);

if (!result.Matched)
    return Unauthorized(MessageFor(result.Failure));
```

Verify and sign in within the same server operation. An endpoint that only verifies, followed by a sign-in that accepts "the face was verified" from the caller, verifies nothing.

`FaceVerificationFailureType` tells which message helps: capturing again fixes `FaceNotDetected`, `LowImageQuality` and `MultipleFaces`, but never `FaceNotOnRecord`. An invalid CPF and an empty image are refused before SERPRO is called, since each call is billed.

`AcceptedLiveness` is empty by default, which leaves the liveness decision to SERPRO and only reports the value in `FaceVerification.Liveness`. Once it lists the values the contracted API version documents, a capture whose liveness is missing or not listed is refused whatever its similarity.

Neither the image nor the CPF is stored or logged.

### Changing Provider

Everything above the registration depends on `ICertificateAuthenticator` or `IFaceVerifier` from `NuvTools.Security`. Another provider is a class implementing the contract — in a package of its own, so its dependencies reach only those who choose it — and one line changed at startup:

```csharp
// builder.Services.AddSerproFaceVerification(builder.Configuration);
builder.Services.AddOtherProviderFaceVerification(builder.Configuration);
```

Options stay with each provider (`RestPkiOptions`, `DatavalidOptions`), since credentials and thresholds are the provider's vocabulary; results and failure reasons are the contract's.

Both registrations take an optional section name, for an application whose settings already live under another one:

```csharp
builder.Services.AddSerproFaceVerification(builder.Configuration, sectionName: "SerproBiometria");
```

## Features

- **Multi-targeting**: Compatible with .NET 8, .NET 9, and .NET 10
- **Comprehensive documentation**: Full XML documentation for IntelliSense
- **Modular design**: Use only what you need
- **Modern C# features**: Uses nullable reference types, implicit usings, and primary constructors

## Building from Source

This project uses the modern `.slnx` solution format (Visual Studio 2022 v17.11+).

```bash
# Clone the repository
git clone https://github.com/nuvtools/nuvtools-security.git
cd nuvtools-security

# Build the solution
dotnet build NuvTools.Security.slnx

# Run tests
dotnet test NuvTools.Security.slnx

# Create release packages
dotnet build NuvTools.Security.slnx --configuration Release
```

## Releasing

Publishing to nuget.org is irreversible per version, so the workflow makes it the last and smallest
step.

**One workflow per library.** Each package has its own, so a run and an approval each concern
exactly one package. The steps themselves are shared, in the reusable `package-publish.yml`.

| Package | Workflow | Release tag |
|---|---|---|
| `NuvTools.Security` | `security-publish.yml` | `security-vX.Y.Z` |
| `NuvTools.Security.AspNetCore` | `aspnetcore-publish.yml` | `aspnetcore-vX.Y.Z` |
| `NuvTools.Security.AspNetCore.Blazor` | `blazor-publish.yml` | `blazor-vX.Y.Z` |
| `NuvTools.Security.Certificate.Lacuna` | `certificate-lacuna-publish.yml` | `certificate-lacuna-vX.Y.Z` |
| `NuvTools.Security.Biometrics.Serpro` | `biometrics-serpro-publish.yml` | `biometrics-serpro-vX.Y.Z` |

1. Set the package's `<Version>` in its `.csproj` and merge it. That is the version that gets
   published; the workflow reads it and never computes one.
2. Run the library's workflow by hand (*Actions → Security Publish → Run workflow*) with *push*
   checked.
3. The workflow builds the solution with `-warnaserror`, runs the tests, takes **that package only**
   from the build output, verifies it carries its README, licence, icon, symbols and every target
   framework, and then waits for approval on the `nuget` GitHub Environment before pushing.
4. **After the push succeeds, the workflow tags the commit** with the tag in the table above. The tag is a
   record of what is on nuget.org, never what starts a release, so it cannot exist for a version
   that did not get there. A run whose tag already exists stops before building: the version has
   been released and `<Version>` needs a bump.

**`NuvTools.Security` goes first.** Every other package references it as a project, so each of them
depends on whatever `<Version>` `NuvTools.Security` has in that commit. The workflow checks that
version is on nuget.org and refuses to push a package whose dependency is not there yet.

That check knows a version exists, not what is in it. **When `NuvTools.Security` gains a type
another package uses, bump its `<Version>` and publish it before the package that uses the type** —
otherwise that package is published against an older `NuvTools.Security` that does not have it, and
fails for whoever installs it.

**Versions published by hand are refused.** Releases made before these workflows exist on nuget.org
with no tag. Pushing one again would skip the duplicate and then tag the current commit as a
release it is not, so a version that is already on nuget.org stops the run. The exception is a
re-run of the same run, which is how a push that succeeded and a tag that failed gets finished.

**No API key is stored.** The push uses nuget.org's trusted publishing: the job presents a GitHub
OIDC token, nuget.org checks it against the policy registered for this repository and answers with a
key that lives for one hour. The repository needs one secret, `NUGET_USER` — the nuget.org profile
name the policy belongs to — and the policy itself, registered under *Trusted Publishing* on
nuget.org with the owner `nuvtools`, the repository `nuvtools-security`, the workflow file and the
environment `nuget`.

Run a library's workflow by hand with *push* unchecked for a dry run that stops after the
verification.

## Requirements

- .NET 8.0 SDK or higher
- Visual Studio 2022 (v17.11+) or Visual Studio Code with C# extension
- NuvTools.AspNetCore.Blazor (for NuvTools.Security.AspNetCore.Blazor)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Links

- [GitHub Repository](https://github.com/nuvtools/nuvtools-security)
- [NuGet Package - NuvTools.Security](https://www.nuget.org/packages/NuvTools.Security/)
- [NuGet Package - NuvTools.Security.AspNetCore](https://www.nuget.org/packages/NuvTools.Security.AspNetCore/)
- [NuGet Package - NuvTools.Security.AspNetCore.Blazor](https://www.nuget.org/packages/NuvTools.Security.AspNetCore.Blazor/)
- [Official Website](https://nuvtools.com)
