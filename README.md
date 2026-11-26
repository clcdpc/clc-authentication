# CLC Authentication

`clc-authentication` adds Microsoft Entra ID sign-in to ASP.NET Core apps targeting .NET 10. It reads application roles and organization mappings from the Central Library Consortium membership database.

## Install

Run this command from the web app directory.

```sh
dotnet add package clc-authentication
```

## Configure sign-in and membership

Add these sections to `appsettings.json`. Replace the tenant and client IDs with values from your Entra web app registration. Register the app's HTTPS origin followed by `/signin-oidc` as a **Web** redirect URI. Supply the app's client credential through your deployment's secret configuration, for example with the environment variable `AzureAd__ClientSecret`.

```json
{
  "AzureAd": {
    "Instance": "https://login.microsoftonline.com/",
    "TenantId": "<tenant-id>",
    "ClientId": "<client-id>",
    "CallbackPath": "/signin-oidc"
  },
  "Clc": {
    "DatabaseServer": "sql01",
    "ApplicationName": "Catalog"
  }
}
```

`Clc:DatabaseServer` is the SQL Server host or instance serving `clc_web_membership`. The connection uses integrated authentication. Grant the account running the web app read access to `dbo.UsersInRoles` and `dbo.EmailDomains` in that database. Set `Clc:ApplicationName` to the application name used in those tables.

## Register the services

Register the services in `Program.cs` and add the middleware before mapping endpoints.

```csharp
using Clc.Authentication;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddClcAzureAdAuth(builder.Configuration);
builder.Services.AddRequireAuthenticatedClcUser();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "Signed in to Catalog");
app.MapGet("/health", () => "OK").AllowAnonymous();
app.Run();
```

`AddClcAzureAdAuth` configures sign-in and adds membership claims. `AddRequireAuthenticatedClcUser` sets both the default and fallback authorization policies. In this example, even the unannotated `/` endpoint requires a signed-in user whose username domain maps to an organization. Use `AllowAnonymous()` on endpoints that should stay public, as shown for `/health`.
