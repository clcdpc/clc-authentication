using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Microsoft.Identity.Web;

namespace Clc.Authentication
{
    public static class UserExtensions
    {
        public static bool IsAdmin(this ClaimsPrincipal user)
        {
            var ci = (ClaimsIdentity)user.Identity;
            return ci.HasClaim(ci.RoleClaimType, "Admin");
        }

        public static List<Claim> GetGroups(this ClaimsIdentity ci)
        {
            return ci.FindAll("groups").ToList();
        }
    }

    public static class IServiceCollectionExtensions
    {
        public static IServiceCollection AddClcAzureAdAuth(this IServiceCollection services, IConfiguration config)
        {
            const string databaseServerKey = "Clc:DatabaseServer";
            var databaseServer = config[databaseServerKey];
            if (string.IsNullOrWhiteSpace(databaseServer))
                throw new InvalidOperationException($"Configuration setting '{databaseServerKey}' is required.");

            const string applicationNameKey = "Clc:ApplicationName";
            var appName = config[applicationNameKey];
            if (string.IsNullOrWhiteSpace(appName))
                throw new InvalidOperationException($"Configuration setting '{applicationNameKey}' is required.");

            services
                .AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
                .AddMicrosoftIdentityWebApp(config.GetSection("AzureAd"));

            services.AddSingleton<IAuthorizationHandler>(_ => new IsClcUserCheckHandler(databaseServer, appName));
            services.AddSingleton<IClaimsTransformation>(_ => new ClcAzureAdClaimsTransformer(databaseServer, appName));

            return services;
        }
        public static IServiceCollection AddRequireAuthenticatedClcUser(this IServiceCollection services)
        {
            services.AddAuthorization(options =>
            {
                options.DefaultPolicy = new AuthorizationPolicyBuilder()
                   .RequireAuthenticatedUser()
                   .AddRequirements(new IsClcUserRequirement())
                   .Build();

                options.FallbackPolicy = options.DefaultPolicy;
            });

            return services;
        }
    }
}
