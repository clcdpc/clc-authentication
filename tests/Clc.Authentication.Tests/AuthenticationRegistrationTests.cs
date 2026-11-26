using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Clc.Authentication.Tests;

[TestClass]
public sealed class AuthenticationRegistrationTests
{
    [TestMethod]
    public void RegistersAuthenticationWithDatabaseServerAndApplicationName()
    {
        var config = new ConfigurationManager
        {
            ["Clc:DatabaseServer"] = "sql01",
            ["Clc:ApplicationName"] = "Catalog"
        };
        var services = new ServiceCollection();
        services.AddClcAzureAdAuth(config);

        using var provider = services.BuildServiceProvider();
        Assert.IsInstanceOfType<ClcAzureAdClaimsTransformer>(provider.GetRequiredService<IClaimsTransformation>());
    }

    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow(" \t ")]
    public void MissingOrBlankApplicationNameFailsRegistration(string applicationName)
    {
        var config = new ConfigurationManager { ["Clc:DatabaseServer"] = "sql01" };
        if (applicationName != null)
            config["Clc:ApplicationName"] = applicationName;

        var error = Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddClcAzureAdAuth(config));
        StringAssert.Contains(error.Message, "Clc:ApplicationName");
    }

    [TestMethod]
    public void LegacyHostnameAloneFailsRegistration()
    {
        var config = new ConfigurationManager
        {
            ["Clc:Database:Hostname"] = "sql01",
            ["Clc:ApplicationName"] = "Catalog"
        };

        var error = Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddClcAzureAdAuth(config));
        StringAssert.Contains(error.Message, "Clc:DatabaseServer");
    }
}
