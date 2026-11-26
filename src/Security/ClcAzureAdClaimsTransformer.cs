using System;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using Clc.Auth.AzureAd.Data;
using Microsoft.AspNetCore.Authentication;

namespace Clc.Authentication
{
    public class ClcAzureAdClaimsTransformer : IClaimsTransformation
    {
        private const string MembershipIssuer = "urn:clc:authentication:claims-transformer";
        readonly IMembershipLookup db;

        public ClcAzureAdClaimsTransformer(string dbHostname, string appName) : this(new AuthDbHelper(dbHostname, appName))
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(dbHostname);
        }

        internal ClcAzureAdClaimsTransformer(IMembershipLookup db)
        {
            this.db = db;
        }

        public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            if (principal.Identity is ClaimsIdentity identity)
            {
                lock (identity)
                {
                    RefreshClaims(identity);
                }
            }

            return Task.FromResult(principal);
        }

        private void RefreshClaims(ClaimsIdentity identity)
        {
            var username = identity.Name;
            var domain = UsernameDomain.Parse(username);
            if (domain == null)
            {
                RemoveIssuedClaims(identity);
                return;
            }

            var databaseRoles = db.GetRolesForUser(username);
            var organizationId = db.GetOrganizationForDomain(domain);
            RemoveIssuedClaims(identity);

            var groupRoles = identity.GetGroups().Select(group => group.Value)
                .Where(name => name.StartsWith("Clc.", StringComparison.OrdinalIgnoreCase));
            var existingRoles = identity.FindAll(identity.RoleClaimType).Select(claim => claim.Value);
            foreach (var role in databaseRoles.Concat(groupRoles).Except(existingRoles, StringComparer.Ordinal))
                identity.AddClaim(new Claim(identity.RoleClaimType, role, ClaimValueTypes.String, MembershipIssuer));

            if (organizationId.HasValue)
            {
                var value = organizationId.Value.ToString(CultureInfo.InvariantCulture);
                if (!identity.HasClaim("Clc.OrganizationId", value))
                    identity.AddClaim(new Claim("Clc.OrganizationId", value, ClaimValueTypes.String, MembershipIssuer));
            }
        }

        private static void RemoveIssuedClaims(ClaimsIdentity identity)
        {
            foreach (var claim in identity.FindAll(claim => claim.Issuer == MembershipIssuer).ToArray())
                identity.RemoveClaim(claim);
        }
    }

    public static class IIdentityExtensions
    {
        public static string GetPreferredUsername(this IIdentity identity)
        {
            var ci = identity as ClaimsIdentity;

            var username = ci?.FindFirst("preferred_username")?.Value ?? identity?.Name ?? "";
            return username;
        }

        public static string GetDomain(this IIdentity identity)
        {
            return UsernameDomain.Parse(identity.GetPreferredUsername());
        }

        public static T GetClaim<T>(this IIdentity identity, string claimName)
        {
            return ConvertClaim<T>((identity as ClaimsIdentity)?.FindFirst(claimName));
        }

        public static string GetPreferredUsername(this ClaimsPrincipal principal) => principal.Identity?.GetClaim<string>("preferred_username");
        public static int? GetClaimOrganization(this ClaimsPrincipal principal) => principal.Identity.GetClaimOrganization();

        public static string GetPreferredUsername(this IPrincipal principal)
        {
            var ci = (ClaimsIdentity)principal.Identity;

            var username = ci?.FindFirst("preferred_username")?.Value ?? principal?.Identity?.Name ?? "";
            return username;
        }

        public static int? GetClaimOrganization(this IIdentity identity) => identity.GetClaim<int?>("Clc.OrganizationId");

        public static T GetClaim<T>(this IPrincipal principal, string claimName)
        {
            if (principal is ClaimsPrincipal claimsPrincipal)
                return ConvertClaim<T>(claimsPrincipal.FindFirst(claimName));

            return (principal?.Identity).GetClaim<T>(claimName);
        }

        private static T ConvertClaim<T>(Claim claim)
        {
            if (claim == null)
                return default;

            var valueType = Nullable.GetUnderlyingType(typeof(T)) ?? typeof(T);
            return (T)TypeDescriptor.GetConverter(valueType).ConvertFromInvariantString(claim.Value);
        }
    }
}
