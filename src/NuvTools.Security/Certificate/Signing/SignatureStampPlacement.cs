namespace NuvTools.Security.Certificate.Signing;

/// <summary>
/// Where a signature stamp goes: stamps are stacked inside an area of a page, left to right and top to
/// bottom, so a later signature lands after the ones already there.
/// </summary>
/// <param name="PageNumber">The page, starting at 1. A negative number counts from the end: -1 is the last page.</param>
/// <param name="Area">The part of the page the stamps are stacked in.</param>
/// <param name="Width">Width of one stamp, in centimeters.</param>
/// <param name="Height">Height of one stamp, in centimeters.</param>
/// <param name="RowSpacing">Space between two rows of stamps, in centimeters.</param>
public sealed record SignatureStampPlacement(int PageNumber, SignatureStampArea Area, double Width, double Height, double RowSpacing = 0);
