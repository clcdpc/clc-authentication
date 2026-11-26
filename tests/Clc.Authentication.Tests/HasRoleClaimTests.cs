using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Clc.Authentication.Tests;

[TestClass]
public sealed class HasRoleClaimTests
{
    [TestMethod]
    public void AllowsRoleOnSecondIdentityWithDifferentCasing()
    {
        var primary = new ClaimsIdentity();
        var secondary = new ClaimsIdentity([new Claim("app_roles", "aDmIn")],
            "test", ClaimTypes.Name, "app_roles");

        Assert.IsNull(AuthorizeAdmin(primary, secondary));
    }

    [TestMethod]
    public void ForbidsWhenNeitherIdentityHasTheRequiredRole()
    {
        var primary = new ClaimsIdentity([new Claim("Role", "Admin"), new Claim("app_roles", "Admin")],
            "test", ClaimTypes.Name, ClaimTypes.Role);
        var secondary = new ClaimsIdentity([new Claim("app_roles", "Reader")],
            "test", ClaimTypes.Name, "app_roles");

        Assert.IsInstanceOfType<ForbidResult>(AuthorizeAdmin(primary, secondary));
    }

    private static IActionResult AuthorizeAdmin(params ClaimsIdentity[] identities)
    {
        using var services = new ServiceCollection().BuildServiceProvider();
        var httpContext = new DefaultHttpContext { User = new ClaimsPrincipal(identities) };
        var action = new ActionContext(httpContext, new RouteData(), new ActionDescriptor());
        var context = new AuthorizationFilterContext(action, new List<IFilterMetadata>());
        var filter = (IAuthorizationFilter)new HasRoleClaimAttribute("Admin").CreateInstance(services);
        filter.OnAuthorization(context);
        return context.Result;
    }
}
