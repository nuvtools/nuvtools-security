# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NuvTools.Security is a collection of .NET libraries for implementing security features in ASP.NET Core and Blazor applications. The repository contains five NuGet packages that provide JWT handling, cryptography, claims management, authorization policies, Blazor authentication state providers, digital certificate authentication and facial verification.

## Solution Structure

The solution follows a standard .NET library pattern with multi-targeting support:

- **src/NuvTools.Security** - Core security library with JWT helpers, cryptography, claims extensions, and authorization policy builders
- **src/NuvTools.Security.AspNetCore** - ASP.NET Core integration with configuration models and CurrentUserService
- **src/NuvTools.Security.AspNetCore.Blazor** - Blazor authentication state providers (manual and OIDC)
- **src/NuvTools.Security.Certificate.Lacuna** - Lacuna REST PKI implementation of the certificate authentication contract
- **src/NuvTools.Security.Biometrics.Serpro** - SERPRO Datavalid implementation of the facial verification contract
- **tests/NuvTools.Security.Test** - NUnit test project

All libraries target net8, net9, and net10.0 frameworks.

## Build and Test Commands

**Note:** This solution uses the modern `.slnx` (XML-based solution) format introduced in Visual Studio 2022 v17.11.

### Build the solution
```bash
dotnet build NuvTools.Security.slnx
```

### Build in Release mode (generates NuGet packages)
```bash
dotnet build NuvTools.Security.slnx -c Release
```

### Run all tests
```bash
dotnet test NuvTools.Security.slnx
```

### Run tests for a specific project
```bash
dotnet test tests/NuvTools.Security.Test/NuvTools.Security.Test.csproj
```

### Run a specific test
```bash
dotnet test --filter "FullyQualifiedName~TestMethodName"
```

## Architecture and Key Components

### Dependency Flow

The project has the following dependency hierarchy:
- **NuvTools.Security** (core, no project dependencies)
  - Depends on: System.IdentityModel.Tokens.Jwt, Microsoft.AspNetCore.Authorization
- **NuvTools.Security.AspNetCore** (depends on NuvTools.Security)
  - Depends on: Microsoft.Extensions.Options.ConfigurationExtensions, NuvTools.Common
  - Framework reference: Microsoft.AspNetCore.App
- **NuvTools.Security.AspNetCore.Blazor** (depends on NuvTools.Security)
  - Razor Class Library (`Microsoft.NET.Sdk.Razor`) — ships components and static web assets
  - Depends on: NuvTools.AspNetCore.Blazor, NuvTools.Common, Microsoft.AspNetCore.Components.Authorization, Microsoft.AspNetCore.Components.WebAssembly.Authentication, Microsoft.AspNetCore.Components.Web
- **NuvTools.Security.Certificate.Lacuna** (depends on NuvTools.Security)
  - Depends on: Lacuna.RestPki.Client, NuvTools.Common, Microsoft.Extensions.Logging.Abstractions, Microsoft.Extensions.Options.ConfigurationExtensions
- **NuvTools.Security.Biometrics.Serpro** (depends on NuvTools.Security)
  - Depends on: NuvTools.Common, NuvTools.Validation, Microsoft.Extensions.Http, Microsoft.Extensions.Options.ConfigurationExtensions

**Contract and provider never share a package.** The provider-neutral contracts (`ICertificateAuthenticator`, `IFaceVerifier` and their result types) live in `NuvTools.Security`, with no dependency of their own. Each provider is a package named `NuvTools.Security.<Area>.<Provider>`, and it is the only place its SDK or wire format may be referenced. A new provider is a new package; nothing provider-specific goes into `NuvTools.Security`, and neither provider package takes the ASP.NET Core framework reference.

**Never reference `NuvTools.Security.AspNetCore` from a WebAssembly project** — its `Microsoft.AspNetCore.App` framework reference is server-only. Whatever the client also needs (the CAPTCHA contract, for instance) belongs in `NuvTools.Security`, which carries no framework reference.

### NuvTools.Security Library

Core security library providing JWT, cryptography, and claims utilities.

#### Helpers (`NuvTools.Security.Helpers`)

**JwtHelper**
- `Generate()` - Creates signed JWT tokens with claims and expiration using HmacSha256
- `ParseClaimsFromJwt()` - Parses claims from JWT without signature validation (client-side use)
- `GetPrincipalFromExpiredToken()` - Extracts ClaimsPrincipal from expired token (refresh flow)
- `GenerateRefreshToken()` - Creates secure random Base64 refresh tokens
- `IsTokenExpired()` - Checks token expiration via 'exp' claim

**HashHelper**
- `ComputeSHA256Hash()` / `ComputeSHA512Hash()` - Computes hashes returning lowercase hex strings
- `ComputeHash()` - Generic method with algorithm selection via `HashAlgorithmType` enum

**AesEncryptionHelper**
- `EncryptToString()` / `EncryptToBytes()` - AES encryption (format: IV (16 bytes) + ciphertext, SHA-256-derived key)
- `DecryptToString()` / `DecryptToBytes()` - AES decryption; non-Base64 input is returned as-is (legacy fallback)
- AES key size selectable via the `SymmetricAlgorithmType` enum (AES128 / AES192 / AES256)

#### Extensions (`NuvTools.Security.Extensions`)

**ClaimsPrincipalExtensions**
- `GetId()` - Returns NameIdentifier or Sub claim (throws if neither present)
- `GetEmail()` - Returns validated email from multiple claim sources (Email, upn, preferred_username, unique_name)
- `GetName()`, `GetGivenName()`, `GetFamilyName()`, `GetSurname()` - Name claim extraction
- `GetSub()`, `GetNameIdentifier()`, `GetUpn()`, `GetPreferredUsername()`, `GetUniqueName()` - Individual claim getters
- `GetCustomAttributeValues<T>()` - Parses "extension_{name}" claims with type conversion (string, int, double, bool, enum)
- `HasValue<T>()` - Checks if custom attribute contains a specific value

**ClaimExtensions**
- `AddPermission()` - Adds a claim with Permission claim type
- `AddPermissionByClass()` - Adds permission claims from all const string fields in a class via reflection
- `AddByClass()` - Generic version with custom claim type

**AuthorizationOptionsExtensions**
- `AddPolicyWithRequiredPermissionClaim()` - Creates policy requiring Permission claim with specified values
- `AddPolicyWithRequiredClaim()` - Creates policy requiring claim type with values (string overload)
- `AddPolicyWithRequiredClaim()` - Creates policy requiring multiple Claim objects

#### Models (`NuvTools.Security.Models`)

**ClaimTypes** - Custom claim type constants including `Permission`

**ClaimConstants** - Standard claim type strings (Sub, Email, GivenName, FamilyName, Upn, PreferredUsername, UniqueName)

#### CAPTCHA contract (`NuvTools.Security.Captcha`)

Shared by the client that produces the token and the server that validates it. Lives here — not in `NuvTools.Security.AspNetCore` — so Blazor WebAssembly can consume it without pulling the ASP.NET Core shared framework.

**CaptchaDefaults** - Header names (`X-Captcha-Token`, `X-Captcha-Mode`, `X-Captcha-Stepup`), the `captcha-stepup` marker, and the `score`/`checkbox` modes

**CaptchaOptions** - Binds the `Captcha` section: `Enabled`, keys, `MinScore`, `AssessmentBaseUrl`, `FailureMessage`

**ICaptchaVerifier / CaptchaVerification** - Provider-neutral verification contract

**CaptchaHttpRequestExtensions** - `AddCaptchaToken()` attaches the headers to an `HttpRequestMessage`

#### Certificate authentication contract (`NuvTools.Security.Certificate`)

Sign-in with a digital certificate: the server opens a challenge, the client signs it, the server validates the answer.

**ICertificateAuthenticator**
- `StartAsync()` - Opens the authentication and returns the `CertificateChallenge` the client signs; provider failures propagate
- `CompleteAsync(token)` - Returns a `CertificateAuthentication` (`Valid`, `Subject`, `Failure`); never throws for a refused or unreachable provider (fail-closed)

**CertificateSubject** - Name, Email, Cpf, Cnpj, CompanyName read from the validated certificate. The contract does not decide which are required — that is the application's rule.

**CertificateFailureType** - `Rejected` (the provider answered and refused) or `Unavailable` (nothing is known)

#### Facial verification contract (`NuvTools.Security.Biometrics`)

Verification against the face a provider holds on record for a person.

**IFaceVerifier** - `VerifyAsync(FaceVerificationRequest)` returns a `FaceVerification` (`Matched`, `Similarity`, `Liveness`, `Failure`); fail-closed

**FaceVerificationFailureType** - Distinguishes what a new capture can fix (`FaceNotDetected`, `LowImageQuality`, `MultipleFaces`) from what it cannot (`FaceNotOnRecord`), plus `NotMatched`, `LivenessRejected`, `InvalidDocument`, `InvalidImage`, `Rejected`, `Unavailable`

Both contracts must be called inside the sign-in operation itself. Do not add an endpoint that only verifies and a sign-in that trusts a flag from the caller.

#### Network (`NuvTools.Security.Network`)

SSRF protection for outbound HTTP to URLs somebody else supplied.

**NetworkAddressPolicy**
- `IsAllowed(IPAddress)` - Denies loopback, private, link-local (metadata), CGNAT, documentation, multicast, reserved, IPv4-embedding IPv6 prefixes and Azure's `168.63.129.16`; IPv4-mapped addresses are judged as IPv4; `allowedNetworks` override, `additionalDeniedNetworks` extend
- `IsHostAllowed(string)` - Refuses `localhost` and the `.localhost`/`.local`/`.internal` suffixes before any lookup (a second line only)
- `ResolveAllowedAsync(host)` - Resolves and throws `NetworkAddressNotAllowedException` if the name or **any** address is denied
- `PublicOnly` - The default instance

**PublicNetworkConnector**
- `CreateHandler(policy?)` / `Apply(handler, policy?)` / `CreateConnectCallback(policy)` - Checks inside `SocketsHttpHandler.ConnectCallback`, so the checked address is the connected address (no DNS-rebinding gap); every redirect hop passes through it; the proxy is switched off
- Refusals surface as `HttpRequestException` with a `NetworkAddressNotAllowedException` inner exception

Do not replace the socket-level check with a URL or pre-resolution check: the gap between the check and the connection is the vulnerability.

### NuvTools.Security.AspNetCore Library

ASP.NET Core integration for security configuration and user services.

#### Configurations (`NuvTools.Security.AspNetCore.Configurations`)

**SecurityConfigurationSection**
- Configuration model for JWT settings: Issuer, Audience, SecretKey
- Default appsettings section name: "NuvTools.Security"

**ServiceCollectionExtensions**
- `AddSecurityConfiguration()` - Registers SecurityConfigurationSection with IOptions pattern

#### Services (`NuvTools.Security.AspNetCore.Services`)

**CurrentUserService**
- Requires IHttpContextAccessor registration
- Properties: NameIdentifier, RemoteIpAddress, RemotePort, FullRemoteAddress, Claims

#### CAPTCHA (`NuvTools.Security.AspNetCore.Captcha`)

Adaptive anti-bot gate for public endpoints (login, password reset, public queries).

**ValidateCaptchaAttribute / ValidateCaptchaFilter**
- Score mode passes when the token is valid and scores at or above `MinScore`; otherwise the response carries the step-up marker so the client presents the checkbox
- Checkbox mode only requires a valid token — the user already solved the challenge
- Fail-closed: an empty or invalid token never reaches the action

**ReCaptchaEnterpriseVerifier**
- Creates the assessment on the Google Cloud reCAPTCHA Enterprise API; the API key stays server-side
- Network failures are logged and treated as invalid

**CaptchaServiceCollectionExtensions**
- `AddCaptcha(configuration, timeoutInSeconds = 10)` binds the options and registers the verifier with its own HttpClient

### NuvTools.Security.AspNetCore.Blazor Library

Blazor authentication state providers and the client half of the adaptive CAPTCHA.

**ManualAuthenticationStateProvider**
- JWT-based authentication with local storage (uses ILocalStorageService from NuvTools.AspNetCore.Blazor)
- Token storage key: "authToken"
- Authentication type: "manual"
- Methods: `SignInAsync(token)`, `SignOutAsync()`
- Property: `CurrentUser` - Current authenticated ClaimsPrincipal
- Automatically signs out on expired tokens

**OidcAuthenticationStateProvider**
- OIDC/OAuth authentication integration
- Extends RemoteAuthenticationService

#### CAPTCHA (`NuvTools.Security.AspNetCore.Blazor.Captcha`)

**NuvCaptcha component** (`NuvCaptcha.razor` / `NuvCaptcha.razor.cs`)
- Invisible by default (score key); renders the "I'm not a robot" checkbox only on step-up
- `GetTokenAsync()` before submitting, `HandleStepUpAsync(result)` on the response, `ResetAsync()` for a retry (the token is single-use)
- `Class` parameter styles the element hosting the widget — the package ships no CSS of its own

**ICaptchaService / CaptchaService**
- Backed by the `captcha.js` ES module served from `_content/NuvTools.Security.AspNetCore.Blazor/`
- When the provider script cannot load (network, ad blocker, CSP) it returns an empty token instead of hanging; the server rejects an empty token, so the outcome is fail-closed
- Register with `AddCaptcha(configuration)` — only the site keys are read on the client

### NuvTools.Security.Certificate.Lacuna Library

Lacuna REST PKI behind `ICertificateAuthenticator`. The only place Lacuna's SDK is referenced.

**RestPkiCertificateAuthenticator / RestPkiOptions** (`NuvTools.Security.Certificate.Lacuna`)
- Web PKI in the browser (`signWithRestPki`); builds its own `RestPkiClient`, so it does not collide with one the application registers for signing documents
- `SecurityContext`: `PkiBrazil` (default), `LacunaTest`, or a security context id. An unknown value throws — it never falls back, so a typo cannot change which roots are trusted

**LacunaCertificateServiceCollectionExtensions** - `AddLacunaCertificateAuthentication(configuration, sectionName = "RestPki")` binds the section

### NuvTools.Security.Biometrics.Serpro Library

SERPRO Datavalid behind `IFaceVerifier`. The only place Datavalid's wire format is known (`Messages/`, internal).

**DatavalidFaceVerifier / DatavalidOptions** (`NuvTools.Security.Biometrics.Serpro`)
- Datavalid `pf-facial`; an invalid CPF or empty image is refused before the (billed) call
- `MinSimilarity` (default 0.9) and `AcceptedLiveness` (default empty = not enforced, only reported) are the application's decision
- Never logs the CPF or the image

**DatavalidAccessTokenProvider** - Singleton that caches the gateway token (client credentials) and replaces it five minutes before it expires; `Invalidate()` on a 401

**SerproBiometricsServiceCollectionExtensions** - `AddSerproFaceVerification(configuration, sectionName = "Datavalid", timeoutInSeconds = 30)` binds the section

## CI and Releasing

`.github/workflows/ci.yml` builds the solution in Release with `-warnaserror` and runs the tests on every push and pull request to `main`.

Each package has its own manually-run publish workflow (`security-publish.yml`, `aspnetcore-publish.yml`, `blazor-publish.yml`, `certificate-lacuna-publish.yml`, `biometrics-serpro-publish.yml`), all calling the reusable `package-publish.yml`. It reads `<Version>` from the `.csproj` (never computes it), verifies the package, pushes through nuget.org trusted publishing behind the `nuget` environment, and then writes the release tag (`security-vX.Y.Z`, …). See *Releasing* in the README.

- A new package needs its own small workflow file and a row in the README table.
- The SourceLink and symbol settings (`PublishRepositoryUrl`, `EmbedUntrackedSources`, `IncludeSymbols`, `snupkg`) must be in every packable project: the workflow fails a package without its `.snupkg`.
- `NuvTools.Security` is published first. When it gains a type another package uses, its `<Version>` must be bumped and published before that package — the workflow only checks the dependency's version exists.

## Testing

The test project uses NUnit 4.x and targets net10.0. Test files follow the naming convention `{ComponentName}Tests.cs`:
- ClaimsPrincipalExtensionsTests.cs
- HashHelperTests.cs
- AesEncryptionHelperTests.cs
- JwtHelperTests.cs
- Captcha/ValidateCaptchaFilterTests.cs (with `StubCaptchaVerifier`)
- Network/NetworkAddressPolicyTests.cs, Network/PublicNetworkConnectorTests.cs (real `HttpClient` against a loopback listener)
- Certificate/RestPkiOptionsTests.cs, Certificate/RestPkiCertificateAuthenticatorTests.cs (no REST PKI account: options, missing token and an unreachable endpoint)
- Biometrics/DatavalidFaceVerifierTests.cs (through the DI registration, with `StubHttpMessageHandler` and `ManualTimeProvider`)

## Code Style

- Nullable reference types enabled
- Implicit usings enabled
- EnforceCodeStyleInBuild enabled
- XML documentation generation enabled for all libraries
- AnalysisLevel set to latest

## Dependencies

### NuvTools.Security
- System.IdentityModel.Tokens.Jwt [8.15.0,8.16.0)
- Microsoft.AspNetCore.Authorization [10.0.2,10.1.0)

### NuvTools.Security.AspNetCore
- Microsoft.Extensions.Options.ConfigurationExtensions [10.0.2,10.1.0)
- FrameworkReference: Microsoft.AspNetCore.App

### NuvTools.Security.AspNetCore.Blazor
- NuvTools.AspNetCore.Blazor 10.1.0
- NuvTools.Security (project reference)
- Microsoft.AspNetCore.Components.Authorization (version varies by target framework)
- Microsoft.AspNetCore.Components.WebAssembly.Authentication (version varies by target framework)
