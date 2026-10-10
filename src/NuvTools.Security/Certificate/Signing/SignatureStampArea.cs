namespace NuvTools.Security.Certificate.Signing;

/// <summary>A part of a page, given by its distance from each edge, in centimeters.</summary>
/// <param name="Left">Distance from the left edge of the page.</param>
/// <param name="Top">Distance from the top edge of the page.</param>
/// <param name="Right">Distance from the right edge of the page.</param>
/// <param name="Bottom">Distance from the bottom edge of the page.</param>
public sealed record SignatureStampArea(double Left, double Top, double Right, double Bottom);
