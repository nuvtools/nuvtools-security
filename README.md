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

## Installation

Install via NuGet Package Manager:

```bash
# For core security features (JWT, cryptography, claims)
dotnet add package NuvTools.Security

# For ASP.NET Core integration (includes NuvTools.Security)
dotnet add package NuvTools.Security.AspNetCore

# For Blazor authentication state providers
dotnet add package NuvTools.Security.AspNetCore.Blazor
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
