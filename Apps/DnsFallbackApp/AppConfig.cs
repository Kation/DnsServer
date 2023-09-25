using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Proxy;

namespace DnsFallbackApp
{
    internal class AppConfig
    {
        public bool Debug;

        public List<string> Domains;

        public List<string> Ipcidr;

        public AppGeoConfig Geo;

        public List<AppNameServerConfig> NameServers;

        public AppProxyConfig Proxy;
    }

    internal class AppGeoConfig
    {
        public bool IsEnabled;

        public string SubscribeUrl;

        public List<string> Countries;
    }

    internal class AppNameServerConfig
    {
        public string Url;

        public string Ip;

        public DnsTransportProtocol Protocol;

        public int Port;
    }

    internal class AppProxyConfig
    {
        public NetProxyType Type;

        public string Address;

        public int Port;

        public string Username;

        public string Password;
    }
}
