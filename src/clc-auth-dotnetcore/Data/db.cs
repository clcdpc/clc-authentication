using Dapper;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Text;

namespace Clc.Auth.NetCore.Data
{
    public class ClcOptions
    {
        public const string Key = "Clc";

        public string DbServer { get; set; }
        public string ApplicationName { get; set; }
    }

    public class DbHelper
    {
        ClcOptions config;
        public string ConnectionString => $"Server={config.DbServer};Database=clc_web_membership;Trusted_Connection=True;";

        public DbHelper(IConfiguration _config)
        {
            config = _config.GetSection("Clc").Get<ClcOptions>();
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
