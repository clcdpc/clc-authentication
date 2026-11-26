using System;
using System.Net.Mail;

namespace Clc.Authentication;

internal static class UsernameDomain
{
    internal static string Parse(string username)
    {
        if (!MailAddress.TryCreate(username, out var address) ||
            !string.Equals(username, address.Address, StringComparison.Ordinal) ||
            Uri.CheckHostName(address.Host) != UriHostNameType.Dns)
        {
            return null;
        }

        return address.Host;
    }
}
