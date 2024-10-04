using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Session;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddRazorPages();

// Configure logging for debugging
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.SetMinimumLevel(LogLevel.Debug);

// Configure authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = "OAuth2";
})
.AddCookie()
.AddOAuth("OAuth2", options =>
{
    options.ClientId = Environment.GetEnvironmentVariable("OAUTH2_CLIENT_ID") ?? "d8d5624e-ebdd-4075-9fe1-1f3ff1563d09";
    options.ClientSecret = Environment.GetEnvironmentVariable("OAUTH2_CLIENT_SECRET") ?? "1065ce83-ce5f-4a3d-9d84-ca507207c8ce";

    // Set the correct authorization and token endpoints
    options.AuthorizationEndpoint = "https://sso.dev.ppmbg.id/web/signin";
    options.TokenEndpoint = "https://sso.dev.ppmbg.id/oauth/token";

    // Set the callback path
    options.CallbackPath = "/auth/callback";

    options.Scope.Clear();
    //options.Scope.Add("profile");
    //options.Scope.Add("email");

    options.SaveTokens = true;

    // Map the JSON keys to user claims
    //options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
    //options.ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
    //options.ClaimActions.MapJsonKey(ClaimTypes.Email, "email");

    // Configure the events
    options.Events = new OAuthEvents
    {
        // Add custom parameters to the authorization request
        OnRedirectToAuthorizationEndpoint = context =>
        {
            // Generate the state parameter
            string state = context.Options.StateDataFormat.Protect(context.Properties);

            // Build the redirect_uri (application's callback URL)
            // var redirectUri = $"{context.Request.Scheme}://{context.Request.Host}{context.Options.CallbackPath}";

            // Build the query string parameters
            var queryParams = new Dictionary<string, string>
            {
                ["client_id"] = options.ClientId,
                ["state"] = state
            };

            // Build the full authorization URL
            var authorizationUrl = QueryHelpers.AddQueryString(options.AuthorizationEndpoint, queryParams);

            // Redirect to the new authorization URL
            context.Response.Redirect(authorizationUrl);

            return Task.CompletedTask;
        },

        OnCreatingTicket = async context =>
        {
            // Retrieve user info from the user info endpoint
            var request = new HttpRequestMessage(HttpMethod.Get, "https://sso.dev.ppmbg.id/api/userinfo");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);

            var response = await context.Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, context.HttpContext.RequestAborted);
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            using var user = JsonDocument.Parse(json);

            context.RunClaimActions(user.RootElement);
        },

        OnRemoteFailure = context =>
        {
            context.HandleResponse();
            context.Response.Redirect("/auth/login");
            return Task.CompletedTask;
        }
    };
});

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor |
                               Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});


builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30); // Set session timeout
    options.Cookie.HttpOnly = true; // Keamanan: cookie tidak dapat diakses dari JavaScript
    options.Cookie.IsEssential = true; // Wajibkan penggunaan cookie meskipun user menolak cookie non-esensial
});

var app = builder.Build();

app.UseForwardedHeaders();

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseSession();

// Use authentication and authorization
app.UseAuthentication();
app.UseAuthorization();

// Map authentication endpoints
app.MapGet("/auth/login", async context =>
{
    var properties = new AuthenticationProperties { RedirectUri = "/" };

    // The 'state' parameter will be generated automatically
    await context.ChallengeAsync("OAuth2", properties);
});

app.MapGet("/auth/logout", async context =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    context.Response.Redirect("/");
});

app.MapGet("/auth/status", async context =>
{
    if (context.User.Identity?.IsAuthenticated == true)
    {
        context.Response.StatusCode = 200;
        await context.Response.WriteAsync("OK");
    }
    else
    {
        context.Response.StatusCode = 401;
        await context.Response.WriteAsync("Unauthorized");
    }
});

app.MapGet("/auth/callback", async context =>
{
    // Retrieve the code from the query string
    var code = context.Request.Query["code"].FirstOrDefault();
    var state = context.Request.Query["state"].FirstOrDefault();

    if (string.IsNullOrEmpty(code))
    {
        // No code found in the callback, return an error
        context.Response.StatusCode = 400;
        await context.Response.WriteAsync("Authorization code not found.");
        return;
    }

    // Retrieve the redirect URI
    //var redirectUri = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}/auth/callback";

    // Prepare the token request
    var tokenRequestParams = new Dictionary<string, string>
    {
        ["grant_type"] = "authorization_code",
        ["state"] = state,
        ["authorization_code"] = code,
        ["client_id"] = Environment.GetEnvironmentVariable("OAUTH2_CLIENT_ID") ?? "d8d5624e-ebdd-4075-9fe1-1f3ff1563d09",
        ["client_secret"] = Environment.GetEnvironmentVariable("OAUTH2_CLIENT_SECRET") ?? "1065ce83-ce5f-4a3d-9d84-ca507207c8ce"
    };

    var tokenRequestContent = new FormUrlEncodedContent(tokenRequestParams);

    // Send the token request to the OAuth2 server
    var tokenResponse = await context.RequestServices.GetRequiredService<HttpClient>().PostAsync("https://sso.dev.ppmbg.id/api/token", tokenRequestContent);

    if (!tokenResponse.IsSuccessStatusCode)
    {
        // Token request failed
        context.Response.StatusCode = 500;
        await context.Response.WriteAsync("Token exchange failed.");
        return;
    }

    // Parse the token response
    var tokenResponseContent = await tokenResponse.Content.ReadAsStringAsync();
    var tokenResponseJson = JsonDocument.Parse(tokenResponseContent);
    var accessToken = tokenResponseJson.RootElement.GetProperty("access_token").GetString();
    var refreshToken = tokenResponseJson.RootElement.GetProperty("refresh_token").GetString();

    // Validate that we have the access token
    if (string.IsNullOrEmpty(accessToken))
    {
        context.Response.StatusCode = 500;
        await context.Response.WriteAsync("Access token not found.");
        return;
    }

    // Save tokens in session
    context.Session.SetString("AccessToken", accessToken);
    context.Session.SetString("RefreshToken", refreshToken);

    // Retrieve user information from the OAuth2 user info endpoint
    var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, "https://sso.dev.ppmbg.id/api/userinfo");
    userInfoRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

    var userInfoResponse = await context.RequestServices.GetRequiredService<HttpClient>().SendAsync(userInfoRequest);

    if (!userInfoResponse.IsSuccessStatusCode)
    {
        context.Response.StatusCode = 500;
        await context.Response.WriteAsync("Failed to retrieve user information.");
        return;
    }

    var userInfoContent = await userInfoResponse.Content.ReadAsStringAsync();
    var userInfoJson = JsonDocument.Parse(userInfoContent);

    // Create the authentication properties and sign the user in
    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.NameIdentifier, userInfoJson.RootElement.GetProperty("id").GetString() ?? string.Empty),
        new Claim(ClaimTypes.Name, userInfoJson.RootElement.GetProperty("name").GetString() ?? string.Empty)
        // Add other claims as necessary
    };

    var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

    // Sign in the user
    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, claimsPrincipal);

    // Redirect to the originally requested page or home
    var returnUrl = context.Request.Query["state"].FirstOrDefault() ?? "/";
    context.Response.Redirect(returnUrl);
});

app.MapRazorPages();


app.Run();
