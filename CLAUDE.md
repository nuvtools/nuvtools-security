# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NuvTools.Security is a collection of .NET libraries for implementing security features in ASP.NET Core and Blazor applications. The repository contains three NuGet packages that provide JWT handling, cryptography, claims management, authorization policies, and Blazor authentication state providers.

## Solution Structure

The solution follows a standard .NET library pattern with multi-targeting support:

- **src/NuvTools.Security** - Core security library with JWT helpers, cryptography, claims extensions, and authorization policy builders
- **src/NuvTools.Security.AspNetCore** - ASP.NET Core integration with configuration models and CurrentUserService
- **src/NuvTools.Security.AspNetCore.Blazor** - Blazor authentication state providers (manual and OIDC)
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
- **NuvTools.Security.AspNetCore** (no project dependencies)
  - Depends on: Microsoft.Extensions.Options.ConfigurationExtensions
  - Framework reference: Microsoft.AspNetCore.App
- **NuvTools.Security.AspNetCore.Blazor** (depends on NuvTools.Security)
  - Depends on: NuvTools.AspNetCore.Blazor, Microsoft.AspNetCore.Components.Authorization, Microsoft.AspNetCore.Components.WebAssembly.Authentication

### NuvTools.Security Library

Core security library providing JWT, cryptography, and claims utilities.

#### Helpers (`NuvTools.Security.Helpers`)

**JwtHelper**
- `Generate()` - Creates signed JWT tokens with claims and expiration using HmacSha256
- `ParseClaimsFromJwt()` - Parses claims from JWT without signature validation (client-side use)
- `GetPrincipalFromExpiredToken()` - Extracts ClaimsPrincipal from expired token (refresh flow)
- `GenerateRefreshToken()` - Creates secure random Base64 refresh tokens
- `IsTokenExpired()` - Checks token expiration via 'exp' claim

**CryptographyHelper**
- `ComputeSHA256Hash()` / `ComputeSHA512Hash()` - Computes hashes returning lowercase hex strings
- `ComputeHash()` - Generic method with algorithm selection via `HashAlgorithmType` enum

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

### NuvTools.Security.AspNetCore.Blazor Library

Blazor authentication state providers.

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

## Testing

The test project uses NUnit 4.x and targets net10.0. Test files follow the naming convention `{ComponentName}Tests.cs`:
- ClaimsPrincipalExtensionsTests.cs
- CryptographyHelperTests.cs
- JwtHelperTests.cs

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
