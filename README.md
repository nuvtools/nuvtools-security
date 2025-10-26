# Nuv Tools Security Libraries

This repository provides a set of libraries for implementing security features in .NET applications, including general-purpose security utilities, ASP.NET Core integrations, and Blazor authentication helpers.

## Libraries Overview

### NuvTools.Security
Common library for security purposes.
Includes helpers for cryptography, hashing, and other security-related utilities.

### NuvTools.Security.AspNetCore
Common library for security purposes in ASP.NET Core.
Provides configuration models and helpers for managing authentication, authorization, and security settings.

### NuvTools.Security.AspNetCore.Blazor
A helper library for managing authentication and security-related tasks in Blazor applications.
Facilitates manual and OIDC-based authentication state management.

## Getting Started

1. **Install via NuGet:**
   - Search for the desired package on NuGet or use the following commands:
     ```
     dotnet add package NuvTools.Security
     dotnet add package NuvTools.Security.AspNetCore
     dotnet add package NuvTools.Security.AspNetCore.Blazor
     ```

2. **Usage Example:**
   - **Hashing a string:**
     ```csharp
     using NuvTools.Security.Helpers;

     string hash = CryptographyHelper.ComputeSHA256Hash("your-value");
     ```
   - **ASP.NET Core Security Configuration:**
     ```csharp
     // appsettings.json
     {
       "NuvTools.Security": {
         "Issuer": "your-issuer",
         "Audience": "your-audience",
         "SecretKey": "your-secret-key"
       }
     }
     ```
     ```csharp
     using NuvTools.Security.AspNetCore.Configurations;

     var config = configuration.GetSection("NuvTools.Security").Get<SecurityConfigurationSection>();
     ```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Publishing

To publish packages to your NuGet source, use: