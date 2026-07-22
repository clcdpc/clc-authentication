using Clc.Auth.AzureAd.Security;
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

namespace Clc.Auth
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
            services
                .AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
                .AddMicrosoftIdentityWebApp(config.GetSection("AzureAd"));

            services.AddSingleton<IAuthorizationHandler, IsClcUserCheckHandler>();
            services.AddSingleton<IClaimsTransformation, ClcAzureAdClaimsTransformer>();

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
