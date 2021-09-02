using System.Data.SqlClient;
using System.Security.Claims;
using System.Threading.Tasks;
using Clc.Auth.NetCore.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;

namespace Clc.Auth.NetCore.Security
{
    public class ClcAzureAdClaimsTransformer : IClaimsTransformation
    {
        public IConfiguration config;

        public ClcAzureAdClaimsTransformer(IConfiguration _config)
        {
            config = _config;
        }

        public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            var ci = (ClaimsIdentity)principal.Identity;
            var db = new DbHelper(config);
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