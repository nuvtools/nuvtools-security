using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using NuvTools.Security.AspNetCore.RateLimiting;

namespace NuvTools.Security.Test.RateLimiting;

[TestFixture]
public class RateLimiterOptionsExtensionsTests
{
    private const string SignIn = "SignIn";
    private const string SignUp = "SignUp";

    private static RequestDelegate CreatePipeline()
    {
        var services = new ServiceCollection()
            .AddLogging()
            .AddRateLimiter(options =>
            {
                options.AddFixedWindowPerClientAddress(SignIn, permitLimit: 2, TimeSpan.FromMinutes(5));
                options.AddFixedWindowPerClientAddress(SignUp, permitLimit: 1, TimeSpan.FromMinutes(5));
                options.OnRejected = (context, _) =>
                {
                    context.SetTooManyRequests();
                    return ValueTask.CompletedTask;
                };
            })
            .BuildServiceProvider();

        var app = new ApplicationBuilder(services);
        app.UseRateLimiter();
        app.Run(context =>
        {
            context.Response.StatusCode = StatusCodes.Status200OK;
            return Task.CompletedTask;
        });

        return app.Build();
    }

    private static async Task<HttpContext> SendAsync(RequestDelegate pipeline, string policy, string? address)
    {
        var context = new DefaultHttpContext();

        if (address is not null)
            context.Connection.RemoteIpAddress = IPAddress.Parse(address);

        context.SetEndpoint(new Endpoint(null, new EndpointMetadataCollection(new EnableRateLimitingAttribute(policy)), policy));

        await pipeline(context);

        return context;
    }

    [Test]
    public async Task RejectsTheRequestPastTheLimit_WithRetryAfter()
    {
        var pipeline = CreatePipeline();

        var first = await SendAsync(pipeline, SignIn, "10.0.0.1");
        var second = await SendAsync(pipeline, SignIn, "10.0.0.1");
        var third = await SendAsync(pipeline, SignIn, "10.0.0.1");

        Assert.Multiple(() =>
        {
            Assert.That(first.Response.StatusCode, Is.EqualTo(StatusCodes.Status200OK));
            Assert.That(second.Response.StatusCode, Is.EqualTo(StatusCodes.Status200OK));
            Assert.That(third.Response.StatusCode, Is.EqualTo(StatusCodes.Status429TooManyRequests));
            Assert.That(int.Parse(third.Response.Headers.RetryAfter.ToString()), Is.InRange(1, 300));
        });
    }

    [Test]
    public async Task CountsEachAddressApart()
    {
        var pipeline = CreatePipeline();

        await SendAsync(pipeline, SignUp, "10.0.0.1");
        var otherAddress = await SendAsync(pipeline, SignUp, "10.0.0.2");

        Assert.That(otherAddress.Response.StatusCode, Is.EqualTo(StatusCodes.Status200OK));
    }

    [Test]
    public async Task CountsEachPolicyApart()
    {
        var pipeline = CreatePipeline();

        await SendAsync(pipeline, SignUp, "10.0.0.1");
        var otherPolicy = await SendAsync(pipeline, SignIn, "10.0.0.1");

        Assert.That(otherPolicy.Response.StatusCode, Is.EqualTo(StatusCodes.Status200OK));
    }

    [Test]
    public async Task RequestsWithoutAnAddress_ShareOneBucket()
    {
        var pipeline = CreatePipeline();

        await SendAsync(pipeline, SignUp, null);
        var second = await SendAsync(pipeline, SignUp, null);

        Assert.That(second.Response.StatusCode, Is.EqualTo(StatusCodes.Status429TooManyRequests));
    }

    [Test]
    public void RejectsAnInvalidLimit()
    {
        var options = new RateLimiterOptions();

        Assert.Multiple(() =>
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => options.AddFixedWindowPerClientAddress(SignIn, 0, TimeSpan.FromMinutes(1)));
            Assert.Throws<ArgumentOutOfRangeException>(() => options.AddFixedWindowPerClientAddress(SignIn, 1, TimeSpan.Zero));
            Assert.Throws<ArgumentException>(() => options.AddFixedWindowPerClientAddress(" ", 1, TimeSpan.FromMinutes(1)));
        });
    }
}
