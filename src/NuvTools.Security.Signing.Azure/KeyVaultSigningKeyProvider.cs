using Azure.Core;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Concurrent;

namespace NuvTools.Security.Signing.Azure;

/// <summary>
/// Signs with an RSA key kept in Azure Key Vault. The private key never leaves the vault: this
/// process holds the public half of each version and asks the vault for every signature.
/// </summary>
/// <remarks>
/// <para>
/// Every enabled version of the key that is within its validity period is offered, so tokens
/// signed before a rotation keep validating. A new version starts signing once it has been
/// published for <see cref="KeyVaultSigningOptions.ActivationDelay"/>.
/// </para>
/// <para>
/// The list of versions is read again every <see cref="KeyVaultSigningOptions.RefreshInterval"/>.
/// When the vault cannot be reached for that, the last list read keeps being served: a rotation
/// noticed late is better than no token at all.
/// </para>
/// <para>
/// The identity used needs to list and read the key and to sign with it — the
/// <c>Key Vault Crypto User</c> role covers both.
/// </para>
/// </remarks>
public class KeyVaultSigningKeyProvider : ISigningKeyProvider, IDisposable
{
    private readonly KeyClient _keys;
    private readonly Func<KeyVaultKey, CryptographyClient> _cryptography;
    private readonly KeyVaultSigningOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger<KeyVaultSigningKeyProvider> _logger;

    // A version of a key never changes, so what was built for one is kept for good.
    private readonly ConcurrentDictionary<string, RemoteRsaSecurityKey> _byVersion = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _refreshing = new(1, 1);

    private IReadOnlyList<SigningCredentials>? _current;
    private DateTimeOffset _readOn;

    /// <summary>
    /// Creates the provider.
    /// </summary>
    /// <param name="keys">The client for the vault holding the key.</param>
    /// <param name="credential">The identity the signatures are requested with.</param>
    /// <param name="options">Which key to use and how its rotation is followed.</param>
    /// <param name="time">The clock the activation delay and the refresh are measured on.</param>
    /// <param name="logger">Where a failed refresh is reported.</param>
    public KeyVaultSigningKeyProvider(
        KeyClient keys,
        TokenCredential credential,
        IOptions<KeyVaultSigningOptions> options,
        TimeProvider time,
        ILogger<KeyVaultSigningKeyProvider> logger)
        : this(keys, key => new CryptographyClient(key.Id, credential), options, time, logger)
    {
        ArgumentNullException.ThrowIfNull(credential);
    }

    internal KeyVaultSigningKeyProvider(
        KeyClient keys,
        Func<KeyVaultKey, CryptographyClient> cryptography,
        IOptions<KeyVaultSigningOptions> options,
        TimeProvider time,
        ILogger<KeyVaultSigningKeyProvider> logger)
    {
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(cryptography);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);
        ArgumentNullException.ThrowIfNull(logger);

        _keys = keys;
        _cryptography = cryptography;
        _options = options.Value;
        _time = time;
        _logger = logger;

        ArgumentException.ThrowIfNullOrWhiteSpace(_options.KeyName);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<SigningCredentials>> GetSigningCredentialsAsync(CancellationToken cancellationToken = default)
    {
        if (_current is { } fresh && _time.GetUtcNow() - _readOn < _options.RefreshInterval)
            return fresh;

        await _refreshing.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            if (_current is { } refreshed && _time.GetUtcNow() - _readOn < _options.RefreshInterval)
                return refreshed;

            try
            {
                _current = await ReadAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (_current is not null && exception is not OperationCanceledException)
            {
                _logger.LogWarning(exception,
                    "The versions of signing key {KeyName} could not be read; the previous list stays in use.",
                    _options.KeyName);
            }

            // Stamped on a failure too, so an unreachable vault is asked again after the interval
            // rather than on every token.
            _readOn = _time.GetUtcNow();

            return _current!;
        }
        finally
        {
            _refreshing.Release();
        }
    }

    private async Task<IReadOnlyList<SigningCredentials>> ReadAsync(CancellationToken cancellationToken)
    {
        var now = _time.GetUtcNow();
        var usable = new List<SigningKeyVersion>();

        await foreach (var version in _keys.GetPropertiesOfKeyVersionsAsync(_options.KeyName, cancellationToken).ConfigureAwait(false))
        {
            if (version.Enabled == true
                && (version.NotBefore is null || version.NotBefore <= now)
                && (version.ExpiresOn is null || version.ExpiresOn > now))
            {
                usable.Add(new SigningKeyVersion(version.Version, version.CreatedOn ?? DateTimeOffset.MinValue));
            }
        }

        if (usable.Count == 0)
            throw new InvalidOperationException(
                $"Key '{_options.KeyName}' has no enabled version within its validity period, so there is nothing to sign with.");

        var credentials = new List<SigningCredentials>(usable.Count);

        foreach (var version in SigningKeyOrder.Arrange(usable, now, _options.ActivationDelay))
        {
            if (!_byVersion.TryGetValue(version.Version, out var key))
            {
                key = await LoadAsync(version.Version, cancellationToken).ConfigureAwait(false);
                _byVersion[version.Version] = key;
            }

            credentials.Add(key.ToSigningCredentials());
        }

        return credentials;
    }

    private async Task<RemoteRsaSecurityKey> LoadAsync(string version, CancellationToken cancellationToken)
    {
        KeyVaultKey key = await _keys.GetKeyAsync(_options.KeyName, version, cancellationToken).ConfigureAwait(false);

        if (key.KeyType != KeyType.Rsa && key.KeyType != KeyType.RsaHsm)
            throw new InvalidOperationException(
                $"Key '{_options.KeyName}' is of type {key.KeyType}; only RSA keys are supported.");

        using var rsa = key.Key.ToRSA(includePrivateParameters: false);
        var client = _cryptography(key);

        // Synchronous on purpose: the token handler's signing call is synchronous, and it is the
        // only caller.
        return new RemoteRsaSecurityKey(
            rsa.ExportParameters(includePrivateParameters: false),
            version,
            data => client.SignData(SignatureAlgorithm.RS256, data).Signature);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _refreshing.Dispose();
        GC.SuppressFinalize(this);
    }
}
