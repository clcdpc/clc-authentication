using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace Clc.Auth.NetCore
{
    public static class UserExtensions
    {
        public static bool IsAdmin(this ClaimsPrincipal user)
        {
            var ci = (ClaimsIdentity)user.Identity;
            return ci.HasClaim(ci.RoleClaimType, "Admin");
        }
    }
}
