# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NuvTools.Security is a collection of .NET libraries for implementing security features in ASP.NET Core and Blazor applications. The repository contains four main NuGet packages that provide JWT handling, cryptography, claims management, authorization policies, and Blazor authentication state providers.

## Solution Structure

The solution follows a standard .NET library pattern with multi-targeting support:

- **src/NuvTools.Security** - Core security library with JWT helpers, cryptography, and claims extensions
- **src/NuvTools.Security.AspNetCore** - ASP.NET Core integration with configuration models and CurrentUserService
- **src/NuvTools.Security.AspNetCore.Blazor** - Blazor authentication state providers (manual and OIDC)
- **src/NuvTools.Security.AspNetCore.Extensions** - Authorization policy builder extensions
- **tests/NuvTools.Security.Test** - NUnit test project

All libraries target net8, net9, and net10.0 frameworks.

## Build and Test Commands

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
dotnet test
```

### Run tests for a specific project
```bash
dotnet test tests/NuvTools.Security.Test/NuvTools.Security.Test.csproj
```

### Run a specific test
```bash
dotnet test --filter "FullyQualifiedName~TestMethodName"
```

### Clean solution
```bash
dotnet clean
```

### Restore dependencies
```bash
dotnet restore
```

## Architecture and Key Components

### Dependency Flow

The project has the following dependency hierarchy:
- **NuvTools.Security** (core, no project dependencies)
  - Depends on: NuvTools.Validation, System.IdentityModel.Tokens.Jwt
- **NuvTools.Security.AspNetCore** (depends on core)
  - Framework dependency: Microsoft.AspNetCore.App
- **NuvTools.Security.AspNetCore.Blazor** (depends on core)
  - Depends on: Blazored.LocalStorage, Microsoft.AspNetCore.Components.Authorization
- **NuvTools.Security.AspNetCore.Extensions** (depends on core)
  - Depends on: Microsoft.AspNetCore.Authorization

### Core Components

**JwtHelper (src/NuvTools.Security/Helpers/JwtHelper.cs)**
- Generates signed JWT tokens with claims and expiration
- Parses claims from JWT without signature validation (useful for client-side)
- Validates expired tokens to extract ClaimsPrincipal (for refresh token flows)
- Generates secure refresh tokens
- Checks token expiration via 'exp' claim
- Uses HmacSha256 signing algorithm exclusively

**CryptographyHelper (src/NuvTools.Security/Helpers/CryptographyHelper.cs)**
- Computes SHA256 and SHA512 hashes
- Returns lowercase hexadecimal hash strings
- Used for password hashing, data integrity checks, etc.

**ClaimsPrincipalExtensions (src/NuvTools.Security/Extensions/ClaimsPrincipalExtensions.cs)**
- Extracts common user identity information from ClaimsPrincipal
- Handles multiple claim type variations (e.g., email can come from multiple claim types)
- GetId() tries both NameIdentifier and Sub claims
- GetEmail() validates email format and checks multiple claim sources
- GetCustomAttributeValues<T>() parses custom extension attributes with type conversion

**SecurityConfigurationSection (src/NuvTools.Security.AspNetCore/Configurations/SecurityConfigurationSection.cs)**
- Configuration model for JWT settings (Issuer, Audience, SecretKey)
- Default appsettings section name is "NuvTools.Security"
- Register using AddSecurityConfiguration() extension method

**CurrentUserService (src/NuvTools.Security.AspNetCore/Services/CurrentUserService.cs)**
- Provides current authenticated user information via dependency injection
- Exposes NameIdentifier, RemoteIpAddress, RemotePort, FullRemoteAddress, and Claims
- Requires IHttpContextAccessor to be registered

**ManualAuthenticationStateProvider (src/NuvTools.Security.AspNetCore.Blazor/ManualAuthenticationStateProvider.cs)**
- Custom Blazor authentication state provider for manual JWT-based auth
- Stores tokens in browser local storage (key: "authToken")
- Automatically signs out users when tokens expire
- Use SignInAsync(token) and SignOutAsync() for authentication state management
- Alternative to built-in OIDC authentication when custom auth logic is needed

**AuthorizationOptionsExtensions (src/NuvTools.Security.AspNetCore.Extensions/AuthorizationOptionsExtensions.cs)**
- Fluent API for building authorization policies
- AddPolicyWithRequiredClaim() - creates policies based on claim type and values
- AddPolicyWithRequiredPermissionClaim() - convenience method for Permission claim type policies

## Testing

The test project uses NUnit framework and targets net10.0. Test files follow the naming convention `{ComponentName}Tests.cs`:
- ClaimsPrincipalExtensionsTests.cs
- CryptographyHelperTests.cs
- JwtHelperTests.cs

## Package Publishing

All projects have `GeneratePackageOnBuild` set to true, so NuGet packages are automatically generated during Release builds. The current version across all packages is 10.0.0.

Package metadata includes:
- Authors: Nuv Tools
- License: MIT (LICENSE file included in packages)
- Repository: https://github.com/nuvtools/nuvtools-security
- Icon: icon.png (in repository root)
- README.md included in packages

## Code Style

- LangVersion: latest
- Nullable reference types enabled
- Implicit usings enabled
- EnforceCodeStyleInBuild enabled
- XML documentation generation enabled for all libraries
- AnalysisLevel set to latest

## Common Development Patterns

### Working with JWT tokens
When adding or modifying JWT functionality, note that:
- The library uses System.IdentityModel.Tokens.Jwt for token handling
- Only HmacSha256 algorithm is supported for signing
- ParseClaimsFromJwt() handles special "roles" claim conversion to ClaimTypes.Role
- Expired token validation is used for refresh token scenarios via GetPrincipalFromExpiredToken()

### Claims handling
The library defines custom claim types in Models/ClaimTypes.cs and ClaimConstants.cs. When working with claims:
- Use ClaimsPrincipalExtensions for consistent claim extraction
- Email extraction tries multiple claim sources and validates format
- Custom extension attributes use "extension_{attributeName}" format

### ASP.NET Core integration
When extending ASP.NET Core features:
- CurrentUserService requires IHttpContextAccessor registration
- SecurityConfigurationSection uses IOptions pattern
- Authorization extensions build on Microsoft.AspNetCore.Authorization

### Blazor authentication
When working with Blazor auth features:
- ManualAuthenticationStateProvider is for custom auth, not OIDC scenarios
- Token storage key is "authToken" in local storage
- Authentication type is set to "manual" for ClaimsIdentity
- OidcAuthenticationStateProvider exists for OIDC-based flows
