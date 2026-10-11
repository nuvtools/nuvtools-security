using Microsoft.IdentityModel.Tokens;

namespace NuvTools.Security.Signing;

/// <summary>
/// Creates signatures by asking the delegate. It never verifies: that is done locally, with the
/// public parameters, by a provider of its own.
/// </summary>
internal sealed class RemoteSignatureProvider(SecurityKey key, string algorithm, Func<byte[], byte[]> sign)
    : SignatureProvider(key, algorithm)
{
    public override byte[] Sign(byte[] input)
    {
        ArgumentNullException.ThrowIfNull(input);

        return sign(input);
    }

    public override byte[] Sign(byte[] input, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(input);

        return sign(input.AsSpan(offset, count).ToArray());
    }

    public override bool Sign(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten)
    {
        var signature = sign(data.ToArray());

        if (signature.Length > destination.Length)
        {
            bytesWritten = 0;
            return false;
        }

        signature.CopyTo(destination);
        bytesWritten = signature.Length;
        return true;
    }

    public override bool Verify(byte[] input, byte[] signature)
        => throw new NotSupportedException("This provider only creates signatures.");

    public override bool Verify(byte[] input, int inputOffset, int inputLength, byte[] signature, int signatureOffset, int signatureLength)
        => throw new NotSupportedException("This provider only creates signatures.");

    protected override void Dispose(bool disposing)
    {
    }
}
