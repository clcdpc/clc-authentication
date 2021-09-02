using Clc.Auth.NetCore.Data;
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
        DbHelper db;

        public IsClcUserCheckHandler(IConfiguration _config)
        {
            db = new DbHelper(_config);
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