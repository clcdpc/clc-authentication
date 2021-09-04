using Clc.Configuration;
using Dapper;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Text;

namespace Clc.Auth.NetCore.Data
{
    public class AuthDbHelper
    {
        AppSettings config;
        public string ConnectionString => $"Server={config.DbServer};Database=clc_web_membership;Trusted_Connection=True;";

        public AuthDbHelper(AppSettings _config)
        {
            config = _config;
        }

        public List<string> GetRolesForUser(string username)
        {
            using (var sql = new SqlConnection(ConnectionString))
            {
                var sqlCommand = "select uir.RoleName from clc_web_membership.dbo.UsersInRoles uir where uir.ApplicationName = @application and uir.Username = @username";

                return sql.Query<string>(sqlCommand, new { username, application = config.ApplicationName }).ToList();
            }
        }

        public int GetOrgForUser(string username)
        {
            using (var sql = new SqlConnection(ConnectionString))
            {
                var emailDomain = username.Split('@')[1];
                var sqlCommand = "select ed.LibraryId from clc_web_membership.dbo.EmailDomains ed where ed.ApplicationName = @application and ed.EmailDomain = @emailDomain";

                return sql.QueryFirst<int>(sqlCommand, new { application = config.ApplicationName, emailDomain });
            }
        }

        public List<string> GetDomains()
        {
            using (var sql = new SqlConnection(ConnectionString))
            { 
                var command = "select distinct Domain from OrganizationDomains where Application = @application";

                return sql.Query<string>(command, new { application = config.ApplicationName }).ToList();
            }
        }
    }
}
