using System;
using System.Security.Claims;
using System.Security.Principal;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Clc.Authentication.Tests;

[TestClass]
public sealed class ClaimReadingTests
{
    private const string OrganizationClaim = "Clc.OrganizationId";

    [TestMethod]
    public void ReadsOrganizationIdFromClaimValue()
    {
        var identity = new ClaimsIdentity([new Claim(OrganizationClaim, "42")]);
        var principal = new ClaimsPrincipal(identity);

        Assert.AreEqual(42, identity.GetClaimOrganization());
        Assert.AreEqual(42, principal.GetClaimOrganization());
        Assert.AreEqual(42, ((IPrincipal)principal).GetClaim<int?>(OrganizationClaim));
    }

    [TestMethod]
    public void MissingOrganizationClaimReturnsNull()
    {
        var identity = new ClaimsIdentity();
        var principal = new ClaimsPrincipal(identity);

        Assert.IsNull(identity.GetClaimOrganization());
        Assert.IsNull(principal.GetClaimOrganization());
        Assert.IsNull(((IPrincipal)principal).GetClaim<int?>(OrganizationClaim));
    }

    [TestMethod]
    [DataRow("invalid")]
    [DataRow("")]
    [DataRow(" ")]
    [DataRow("2147483648")]
    public void MalformedOrganizationClaimThrows(string value)
    {
        var identity = new ClaimsIdentity([new Claim(OrganizationClaim, value)]);
        var principal = new ClaimsPrincipal(identity);

        Assert.Throws<ArgumentException>(() => identity.GetClaimOrganization());
        Assert.Throws<ArgumentException>(() => principal.GetClaimOrganization());
        Assert.Throws<ArgumentException>(() => ((IPrincipal)principal).GetClaim<int?>(OrganizationClaim));
    }
}
