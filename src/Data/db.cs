using Dapper;
using System;
using System.Collections.Generic;
using Microsoft.Data.SqlClient;
using System.Linq;
using Clc.Authentication;

namespace Clc.Auth.AzureAd.Data
{
    internal interface IMembershipLookup
    {
        List<string> GetRolesForUser(string username);
        int? GetOrganizationForDomain(string emailDomain);
    }

    public class AuthDbHelper : IMembershipLookup
    {
        readonly string applicationName;
        public string ConnectionString { get; }

        public AuthDbHelper(string dbHostname, string appName)
        {
            applicationName = appName;
            ConnectionString = $"Server={dbHostname};Database=clc_web_membership;Trusted_Connection=True;TrustServerCertificate=True;";
        }

        public List<string> GetRolesForUser(string username)
        {
            using (var sql = new SqlConnection(ConnectionString))
            {
                var sqlCommand = "select distinct uir.RoleName from clc_web_membership.dbo.UsersInRoles uir where (uir.ApplicationName = @application or @application = 'any') and uir.Username = @username";

                return sql.Query<string>(sqlCommand, new { username, application = applicationName }).ToList();
            }
        }

        public int? GetOrgForUser(string username)
        {
            var domain = UsernameDomain.Parse(username);
            return domain == null ? null : GetOrganizationForDomain(domain);
        }

        public int? GetOrganizationForDomain(string emailDomain)
        {
            using (var sql = new SqlConnection(ConnectionString))
            {
                var sqlCommand = """
                    select ed.EmailDomain, ed.LibraryId
                    from clc_web_membership.dbo.EmailDomains ed
                    where (ed.ApplicationName = @application or ed.ApplicationName is null)
                      and ed.EmailDomain = @emailDomain collate Latin1_General_100_CI_AS
                    order by ed.ApplicationName
                    """;
                var candidates = sql.Query<(string Domain, int? OrganizationId)>(sqlCommand, new { application = applicationName, emailDomain });
                // SQL collation can equate domains that differ by more than letter case.
                return candidates.FirstOrDefault(row => string.Equals(row.Domain, emailDomain, StringComparison.OrdinalIgnoreCase)).OrganizationId;
            }
        }

        public List<string> GetDomains()
        {
            using (var sql = new SqlConnection(ConnectionString))
            {
                var command = "select distinct EmailDomain from EmailDomains where ApplicationName = @applicationName or ApplicationName is null";

                return sql.Query<string>(command, new { applicationName }).ToList();
            }
        }
    }
}
