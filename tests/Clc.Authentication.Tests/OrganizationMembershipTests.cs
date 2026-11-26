using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Clc.Auth.AzureAd.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Clc.Authentication.Tests;

[TestClass]
public sealed class OrganizationMembershipTests
{
    [TestMethod]
    public async Task MappedUserGetsOrganizationClaimAndIsAuthorized()
    {
        var lookup = new MembershipLookup(domain => domain == "example.org" ? 42 : null);
        var user = CreateUser("member@example.org");

        await new ClcAzureAdClaimsTransformer(lookup).TransformAsync(user);

        Assert.AreEqual("42", user.FindFirst("Clc.OrganizationId")?.Value);
        Assert.IsTrue(await IsAuthorized(user, lookup));
    }

    [TestMethod]
    public async Task UnmappedUserGetsNoOrganizationClaimAndIsDenied()
    {
        var lookup = new MembershipLookup(domain => null);
        var user = CreateUser("member@unmapped.example");

        await new ClcAzureAdClaimsTransformer(lookup).TransformAsync(user);

        Assert.IsNull(user.FindFirst("Clc.OrganizationId"));
        Assert.IsFalse(await IsAuthorized(user, lookup));
    }

    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("member")]
    [DataRow("member@")]
    [DataRow("@example.org")]
    [DataRow("member@@example.org")]
    [DataRow("member@exa mple.org")]
    [DataRow("Member <member@example.org>")]
    public async Task MalformedUsernameGetsNoOrganizationClaimAndIsDenied(string username)
    {
        var lookup = new MembershipLookup(domain => throw new AssertFailedException("Unexpected lookup for " + domain));
        var user = CreateUser(username);

        await new ClcAzureAdClaimsTransformer(lookup).TransformAsync(user);

        Assert.IsNull(user.FindFirst("Clc.OrganizationId"));
        Assert.IsFalse(await IsAuthorized(user, lookup));
        Assert.AreEqual(0, lookup.RoleLookups);
    }

    [TestMethod]
    public async Task OrganizationLookupErrorsPropagateFromBothPaths()
    {
        var lookup = new MembershipLookup(domain => throw new DataException("Lookup failed."));
        var user = CreateUser("member@example.org");

        await Assert.ThrowsExactlyAsync<DataException>(() => new ClcAzureAdClaimsTransformer(lookup).TransformAsync(user));
        await Assert.ThrowsExactlyAsync<DataException>(() => IsAuthorized(user, lookup));
    }

    [TestMethod]
    public async Task TransformingTwiceProducesOneClaimPerRoleAndOrganization()
    {
        var lookup = new MembershipLookup(_ => 42);
        lookup.Roles.AddRange(["Admin", "Clc.Shared", "Reader"]);
        var identity = new ClaimsIdentity([
            new Claim(ClaimTypes.Name, "member@example.org"),
            new Claim("app_roles", "Reader"),
            new Claim("groups", "Clc.Shared"),
            new Claim("groups", "Clc.GroupOnly")
        ], "test", ClaimTypes.Name, "app_roles");
        var user = new ClaimsPrincipal(identity);
        var transformer = new ClcAzureAdClaimsTransformer(lookup);

        await transformer.TransformAsync(user);
        await transformer.TransformAsync(user);

        CollectionAssert.AreEquivalent(new[] { "Admin", "Reader", "Clc.Shared", "Clc.GroupOnly" },
            identity.FindAll(identity.RoleClaimType).Select(claim => claim.Value).ToArray());
        Assert.IsFalse(identity.FindAll(ClaimTypes.Role).Any());
        Assert.AreEqual("42", identity.FindAll("Clc.OrganizationId").Single().Value);
    }

    [TestMethod]
    [DataRow(73)]
    [DataRow(null)]
    public async Task RefreshUpdatesMembershipAndPreservesProviderClaims(int? nextOrganizationId)
    {
        int? organizationId = 42;
        var lookup = new MembershipLookup(_ => organizationId);
        lookup.Roles.Add("OldRole");
        var user = CreateUser("member@example.org");
        var identity = (ClaimsIdentity)user.Identity;
        var transformer = new ClcAzureAdClaimsTransformer(lookup);
        await transformer.TransformAsync(user);

        var providerRole = new Claim(identity.RoleClaimType, "OldRole", ClaimValueTypes.String, "provider", "provider", identity);
        var providerOrganization = new Claim("Clc.OrganizationId", "99", ClaimValueTypes.String, "provider", "provider", identity);
        identity.AddClaim(providerRole);
        identity.AddClaim(providerOrganization);
        organizationId = nextOrganizationId;
        lookup.Roles.Clear();
        lookup.Roles.Add("NewRole");
        await transformer.TransformAsync(user);

        Assert.AreSame(providerRole, identity.FindAll(identity.RoleClaimType).Single(claim => claim.Value == "OldRole"));
        Assert.IsTrue(identity.HasClaim(identity.RoleClaimType, "NewRole"));
        Assert.AreSame(providerOrganization, identity.FindAll("Clc.OrganizationId").Single(claim => claim.Value == "99"));
        var expectedOrganizations = nextOrganizationId.HasValue ? new[] { "99", "73" } : new[] { "99" };
        CollectionAssert.AreEquivalent(expectedOrganizations, identity.FindAll("Clc.OrganizationId").Select(claim => claim.Value).ToArray());
    }

    private static ClaimsPrincipal CreateUser(string username)
    {
        var identity = new ClaimsIdentity("test");
        if (username != null)
            identity.AddClaim(new Claim(ClaimTypes.Name, username));
        return new ClaimsPrincipal(identity);
    }

    private static async Task<bool> IsAuthorized(ClaimsPrincipal user, IMembershipLookup lookup)
    {
        var requirement = new IsClcUserRequirement();
        var context = new AuthorizationHandlerContext([requirement], user, null);
        await new IsClcUserCheckHandler(lookup).HandleAsync(context);
        return context.HasSucceeded;
    }

    private sealed class MembershipLookup(Func<string, int?> findOrganization) : IMembershipLookup
    {
        public int RoleLookups { get; private set; }
        public List<string> Roles { get; } = [];

        public List<string> GetRolesForUser(string username)
        {
            RoleLookups++;
            return Roles;
        }

        public int? GetOrganizationForDomain(string emailDomain) => findOrganization(emailDomain);
    }
}
