namespace NuvTools.Security;

/// <summary>
/// This contains the options set by the developer and data that is passed between setup extension methods
/// </summary>
public class PermissionsOptions
{
    /// <summary>
    /// ApplicationId default
    /// </summary>
    public required string DefaultApplicationId { get; set; }

    /// <summary>
    /// Internal: holds the type of the Enum Permissions 
    /// </summary>
    public required Enum DefaultEnumPermissionsType { get; set; }
}