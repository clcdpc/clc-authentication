using System.Data.SqlClient;
using System.Security.Claims;
using System.Threading.Tasks;
using Clc.Auth.NetCore.Data;
using Clc.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;

namespace Clc.Auth.NetCore.Security
{
    public class ClcAzureAdClaimsTransformer : IClaimsTransformation
    {
        readonly AuthDbHelper db;

        public ClcAzureAdClaimsTransformer(AppSettings config)
        {
            db = new AuthDbHelper(config);
        }

        public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            var ci = (ClaimsIdentity)principal.Identity;
            var roles = db.GetRolesForUser(ci.Name);

            foreach (var role in roles)
            {
                ci.AddClaim(new Claim(ci.RoleClaimType, role));
            }

            ci.AddClaim(new Claim("orgid", db.GetOrgForUser(ci.Name).ToString()));            

            return Task.FromResult(principal);
        }
    }
}