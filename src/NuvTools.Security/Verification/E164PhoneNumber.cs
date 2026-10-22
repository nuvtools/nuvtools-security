namespace NuvTools.Security.Verification;

/// <summary>
/// Phone numbers in E.164 form: a plus sign, the country calling code and the national number, digits
/// only, at most 15 of them (<c>+5511987654321</c>).
/// </summary>
public static class E164PhoneNumber
{
    private const int MinDigits = 8;
    private const int MaxDigits = 15;

    /// <summary>Whether the value is already a number in E.164 form.</summary>
    /// <param name="value">The value to check.</param>
    public static bool IsValid(string? value)
    {
        if (value is null || value.Length < MinDigits + 1 || value.Length > MaxDigits + 1 || value[0] != '+') return false;

        // A country calling code never starts with zero.
        if (value[1] == '0') return false;

        for (var i = 1; i < value.Length; i++)
            if (!char.IsAsciiDigit(value[i])) return false;

        return true;
    }

    /// <summary>
    /// Turns a number as a person types it into E.164 form.
    /// </summary>
    /// <param name="input">
    /// What was typed: spaces, dots, dashes and parentheses are ignored. A leading <c>+</c> or
    /// <c>00</c> means the country calling code is included; otherwise the number is national.
    /// </param>
    /// <param name="defaultCountryCallingCode">
    /// The country calling code of a national number, digits only (<c>55</c> for Brazil, <c>1</c> for
    /// the United States). A national number's leading trunk zero is dropped.
    /// </param>
    /// <param name="phoneNumber">The number in E.164 form, when the input is one.</param>
    /// <returns>Whether the input is a phone number.</returns>
    public static bool TryNormalize(string? input, string defaultCountryCallingCode, out string phoneNumber)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(defaultCountryCallingCode);

        phoneNumber = string.Empty;

        if (string.IsNullOrWhiteSpace(input)) return false;

        var trimmed = input.Trim();
        var international = trimmed.StartsWith('+');

        var digits = new System.Text.StringBuilder(trimmed.Length);

        foreach (var c in trimmed.AsSpan(international ? 1 : 0))
        {
            if (char.IsAsciiDigit(c)) digits.Append(c);
            else if (c is not (' ' or '.' or '-' or '(' or ')')) return false;
        }

        var number = digits.ToString();

        if (!international && number.StartsWith("00", StringComparison.Ordinal))
        {
            international = true;
            number = number[2..];
        }

        if (!international) number = defaultCountryCallingCode + number.TrimStart('0');

        var candidate = "+" + number;

        if (!IsValid(candidate)) return false;

        phoneNumber = candidate;

        return true;
    }
}
