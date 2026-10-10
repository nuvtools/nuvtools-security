using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using Microsoft.Extensions.Options;
using NuvTools.Security.Biometrics.Serpro.Messages;

namespace NuvTools.Security.Biometrics.Serpro;

/// <summary>
/// Issues and caches the access token for the SERPRO API gateway (client credentials), so a
/// verification does not pay for a token request each time.
/// </summary>
/// <param name="httpClientFactory">Factory for the client used to call the token endpoint.</param>
/// <param name="options">Datavalid configuration.</param>
/// <param name="timeProvider">Clock the token's lifetime is measured with.</param>
public sealed class DatavalidAccessTokenProvider(
    IHttpClientFactory httpClientFactory,
    IOptions<DatavalidOptions> options,
    TimeProvider timeProvider) : IDisposable
{
    /// <summary>Name of the <see cref="HttpClient"/> used to call the token endpoint.</summary>
    public const string HttpClientName = "DatavalidToken";

    // A token is replaced this long before it expires, so one in flight never arrives expired.
    private static readonly TimeSpan RefreshMargin = TimeSpan.FromMinutes(5);

    private readonly DatavalidOptions _options = options.Value;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private string? _token;
    private DateTimeOffset _refreshAt;

    /// <summary>
    /// Returns the cached token, requesting a new one when there is none or it is about to expire.
    /// </summary>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>The access token.</returns>
    /// <exception cref="HttpRequestException">The gateway refused the credentials or could not be reached.</exception>
    /// <exception cref="InvalidOperationException">The gateway answered without a token.</exception>
    public async Task<string> GetAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            if (_token is not null && timeProvider.GetUtcNow() < _refreshAt)
                return _token;

            var response = await RequestAsync(cancellationToken).ConfigureAwait(false);

            if (string.IsNullOrWhiteSpace(response?.AccessToken))
                throw new InvalidOperationException("The SERPRO gateway answered the token request without an access token.");

            var lifetime = TimeSpan.FromSeconds(Math.Max(response.ExpiresIn, 0));
            var margin = lifetime > RefreshMargin + RefreshMargin ? RefreshMargin : lifetime / 2;

            _token = response.AccessToken;
            _refreshAt = timeProvider.GetUtcNow() + lifetime - margin;

            return _token;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Discards the cached token, so the next call requests a new one. Called when the gateway
    /// refuses a token it issued.
    /// </summary>
    public void Invalidate()
    {
        _gate.Wait();

        try
        {
            _token = null;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <inheritdoc />
    public void Dispose() => _gate.Dispose();

    private async Task<DatavalidTokenResponse?> RequestAsync(CancellationToken cancellationToken)
    {
        var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_options.ConsumerKey}:{_options.ConsumerSecret}"));

        using var request = new HttpRequestMessage(HttpMethod.Post, _options.TokenUrl)
        {
            Content = new FormUrlEncodedContent([new KeyValuePair<string, string>("grant_type", "client_credentials")])
        };

        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);

        using var client = httpClientFactory.CreateClient(HttpClientName);
        using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);

        response.EnsureSuccessStatusCode();

        return await response.Content.ReadFromJsonAsync<DatavalidTokenResponse>(cancellationToken).ConfigureAwait(false);
    }
}
