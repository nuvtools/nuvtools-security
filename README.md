# NuvTools.Security

A comprehensive suite of .NET libraries for implementing security features in modern applications, including JWT authentication, cryptography, claims-based authorization, and Blazor authentication state management.

[![NuGet](https://img.shields.io/nuget/v/NuvTools.Security.svg)](https://www.nuget.org/packages/NuvTools.Security/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Features

- 🔐 **JWT Token Management** - Generate, validate, and parse JWT tokens with built-in refresh token support
- 🔒 **Cryptography Helpers** - SHA256 and SHA512 hashing utilities
- 👤 **Claims Principal Extensions** - Easy extraction of user information from claims with multiple fallback sources
- ⚙️ **ASP.NET Core Integration** - Configuration models and current user service
- 🎨 **Blazor Authentication** - Manual and OIDC-based authentication state providers
- 🛡️ **Authorization Extensions** - Fluent API for building permission-based policies

## Supported Frameworks

- .NET 8.0
- .NET 9.0
- .NET 10.0

## Libraries Overview

### NuvTools.Security

Core security library providing JWT token handling, cryptography utilities, and ClaimsPrincipal extensions.

**Key Components:**
- `JwtHelper` - Generate, parse, and validate JWT tokens
- `CryptographyHelper` - Compute SHA256/SHA512 hashes
- `ClaimsPrincipalExtensions` - Extract user info from claims (email, name, custom attributes)
- `ClaimExtensions` - Build claims collections with permission support

```bash
dotnet add package NuvTools.Security
```

### NuvTools.Security.AspNetCore

Security configuration and authenticated user services for ASP.NET Core applications.

**Key Components:**
- `SecurityConfigurationSection` - JWT configuration model (Issuer, Audience, SecretKey)
- `CurrentUserService` - Access current authenticated user and connection details
- `ServiceCollectionExtensions` - DI configuration helpers

```bash
dotnet add package NuvTools.Security.AspNetCore
```

### NuvTools.Security.AspNetCore.Blazor

Authentication state providers for Blazor applications with JWT and OIDC support.

**Key Components:**
- `ManualAuthenticationStateProvider` - JWT-based auth with local storage
- `OidcAuthenticationStateProvider` - OIDC/OAuth authentication integration

```bash
dotnet add package NuvTools.Security.AspNetCore.Blazor
```

### NuvTools.Security.AspNetCore.Extensions

Authorization policy builder extensions for ASP.NET Core.

**Key Components:**
- `AuthorizationOptionsExtensions` - Fluent API for permission and claim-based policies

```bash
dotnet add package NuvTools.Security.AspNetCore.Extensions
```

## Quick Start

### 1. JWT Token Generation and Validation

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
```

### 2. Cryptography and Hashing

```csharp
using NuvTools.Security.Helpers;

// Compute SHA256 hash
string hash256 = CryptographyHelper.ComputeSHA256Hash("sensitive-data");

// Compute SHA512 hash
string hash512 = CryptographyHelper.ComputeSHA512Hash("sensitive-data");

// Generic method with algorithm selection
string hash = CryptographyHelper.ComputeHash(
    "data",
    CryptographyHelper.HashAlgorithmType.SHA512
);
```

### 3. Claims Principal Extensions

```csharp
using NuvTools.Security.Extensions;

// In a controller or service
public class UserController : ControllerBase
{
    public IActionResult GetProfile()
    {
        // Extract user information with automatic fallback
        var userId = User.GetId();                    // NameIdentifier or Sub
        var email = User.GetEmail();                   // Email, upn, preferred_username, etc.
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

### 4. ASP.NET Core Configuration

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
public class MyService
{
    private readonly CurrentUserService _currentUser;

    public MyService(CurrentUserService currentUser)
    {
        _currentUser = currentUser;
    }

    public void DoSomething()
    {
        var userId = _currentUser.NameIdentifier;
        var ipAddress = _currentUser.RemoteIpAddress;
        var fullAddress = _currentUser.FullRemoteAddress;
        var claims = _currentUser.Claims;
    }
}
```

### 5. Blazor Manual Authentication

**Program.cs:**
```csharp
using NuvTools.Security.AspNetCore.Blazor;
using Microsoft.AspNetCore.Components.Authorization;
using Blazored.LocalStorage;

var builder = WebAssemblyHostBuilder.CreateDefault(args);

builder.Services.AddBlazoredLocalStorage();
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

### 6. Authorization Policies with Permissions

**Program.cs:**
```csharp
using NuvTools.Security.AspNetCore.Extensions;
using NuvTools.Security.Models;

builder.Services.AddAuthorization(options =>
{
    // Add policy requiring specific permission claim
    options.AddPolicyWithRequiredPermissionClaim("CanManageUsers", "users.write", "users.delete");

    // Add policy with custom claim type and values
    options.AddPolicyWithRequiredClaim("AdminOnly", "role", "Admin", "SuperAdmin");

    // Add policy with multiple different claims
    options.AddPolicyWithRequiredClaim("ComplexPolicy",
        new Claim(ClaimTypes.Permission, "reports.read"),
        new Claim("department", "IT")
    );
});
```

**Controller:**
```csharp
[Authorize(Policy = "CanManageUsers")]
public class UserManagementController : ControllerBase
{
    [HttpPost]
    public IActionResult CreateUser() { /* ... */ }
}
```

### 7. Building Claims Collections

```csharp
using NuvTools.Security.Extensions;
using NuvTools.Security.Models;

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

## Advanced Usage

### Refresh Token Flow

```csharp
using NuvTools.Security.Helpers;

// When access token expires, get principal from expired token
var principal = JwtHelper.GetPrincipalFromExpiredToken(
    expiredToken,
    "your-secret-key"
);

// Validate refresh token from database
// If valid, generate new access token
var newAccessToken = JwtHelper.Generate(
    key: "your-secret-key",
    issuer: "your-app",
    audience: "your-app-users",
    claims: principal.Claims,
    expires: DateTime.UtcNow.AddHours(1)
);
```

### OIDC Authentication in Blazor

**Program.cs:**
```csharp
using NuvTools.Security.AspNetCore.Blazor;

builder.Services.AddOidcAuthentication(options =>
{
    builder.Configuration.Bind("AzureAd", options.ProviderOptions);
});

// Use custom OIDC provider
builder.Services.AddScoped<AuthenticationStateProvider, OidcAuthenticationStateProvider>();
```

## Repository Information

- **Repository:** [https://github.com/nuvtools/nuvtools-security](https://github.com/nuvtools/nuvtools-security)
- **License:** MIT
- **Authors:** Nuv Tools

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.