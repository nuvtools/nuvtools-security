using System.Net.Http.Headers;

namespace NuvTools.Security.Test.Biometrics;

/// <summary>What a request carried when <see cref="StubHttpMessageHandler"/> received it.</summary>
internal sealed record SentRequest(Uri Uri, AuthenticationHeaderValue? Authorization, string Body);
