namespace NuvTools.Security.Test.Biometrics;

/// <summary>
/// Answers every request from a function and keeps what was sent, so a test can assert on both.
/// </summary>
internal sealed class StubHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
{
    public List<SentRequest> Requests { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // The content is read here: it is disposed with the request once the caller is done.
        var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);

        Requests.Add(new SentRequest(request.RequestUri!, request.Headers.Authorization, body));

        return respond(request);
    }
}
