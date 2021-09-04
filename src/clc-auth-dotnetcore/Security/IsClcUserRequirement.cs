using Clc.Auth.NetCore.Data;
using Clc.Configuration;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Clc.Auth.NetCore.Security
{
    public class IsClcUserRequirement : IAuthorizationRequirement
    {

    }

    public class IsClcUserCheckHandler : AuthorizationHandler<IsClcUserRequirement>
    {
        AuthDbHelper db;

        public IsClcUserCheckHandler(AppSettings config)
        {
            db = new AuthDbHelper(config);
        }

        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, IsClcUserRequirement requirement)
        {
            var ci = (ClaimsIdentity)context.User.Identity;
            var domain = context.User.Identity.Name.Split('@')[1];

            if (ci.IsAuthenticated && db.GetDomains().Any(d => d.Equals(domain, StringComparison.OrdinalIgnoreCase))) { context.Succeed(requirement); }
            return Task.FromResult(0);
        }
    }
}