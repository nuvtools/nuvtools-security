using Microsoft.AspNetCore.Authorization;
using NuvTools.Common.Enums;

namespace NuvTools.Security;

/// <summary>
/// This attribute can be applied in the same places as the [Authorize] would go
/// This will only allow users which has a role containing the enum Permission passed in 
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, Inherited = false)]
public class HasPermissionAttribute<TEnum> : AuthorizeAttribute where TEnum : Enum
{
    /// <summary>
    /// Verifies whether has permission by enum.
    /// </summary>
    /// <param name="permission"></param>
    /// <param name="applicationId"></param>
    public HasPermissionAttribute(TEnum permission, string? applicationId = null) :
                                            base($"{applicationId}|{typeof(TEnum).AssemblyQualifiedName}|{permission.GetValueAsString()}")
    {
    }
}