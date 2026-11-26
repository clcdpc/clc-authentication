using Clc.Auth.AzureAd.Data;
using Microsoft.AspNetCore.Authorization;
using System.Threading.Tasks;

namespace Clc.Authentication
{
    public class IsClcUserRequirement : IAuthorizationRequirement
    {

    }

    public class IsClcUserCheckHandler : AuthorizationHandler<IsClcUserRequirement>, IAuthorizationRequirement
    {
        readonly IMembershipLookup db;

        public IsClcUserCheckHandler(string dbHostname, string appName) : this(new AuthDbHelper(dbHostname, appName))
        {
        }

        internal IsClcUserCheckHandler(IMembershipLookup db)
        {
            this.db = db;
        }

        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, IsClcUserRequirement requirement)
        {
            var identity = context.User.Identity;
            if (identity?.IsAuthenticated == true && UsernameDomain.Parse(identity.Name) is string domain &&
                db.GetOrganizationForDomain(domain).HasValue)
            {
                context.Succeed(requirement);
            }
            return Task.CompletedTask;
        }
    }
}
