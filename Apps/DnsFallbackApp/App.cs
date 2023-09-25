using DnsServerCore.ApplicationCommon;
using MaxMind.GeoIP2;
using MaxMind.GeoIP2.Model;
using MaxMind.GeoIP2.Responses;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Reflection.Metadata;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Proxy;

namespace DnsFallbackApp
{
    public class App : IDnsApplication, IDnsAuthoritativeRequestHandler
    {
        private IDnsServer _dnsServer;
        private AppConfig _config;
        private List<(uint, uint)> _ranges;
        private DatabaseReader _geoDatabase;
        private Task _subscribeTask;
        private CancellationTokenSource _cts;
        private DnsClient _dnsClient;

        public string Description => "Resolve dns contamination problem.";

        private bool _disposed;
        public void Dispose()
        {
            if (_disposed)
                return;
            _disposed = true;
            if (_cts != null)
                _cts.Cancel();
            _dnsClient = null;
            _dnsServer = null;
        }

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;
            try
            {
                _config = JsonSerializer.Deserialize<AppConfig>(config, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    IncludeFields = true,
                    Converters =
                {
                    new System.Text.Json.Serialization.JsonStringEnumConverter()
                }
                });
            }
            catch (Exception ex)
            {
                dnsServer.WriteLog("AntiBadDns: Read config failed.");
                dnsServer.WriteLog(ex);
                return Task.CompletedTask;
            }
            if (_config.Ipcidr != null)
            {
                foreach (var item in _config.Ipcidr)
                {
                    string[] parts = item.Split('.', '/');
                    if (parts.Length != 4)
                        continue;
                    byte a, b, c, d, e;
                    if (!byte.TryParse(parts[0], out a))
                        continue;
                    if (!byte.TryParse(parts[1], out b))
                        continue;
                    if (!byte.TryParse(parts[2], out c))
                        continue;
                    if (!byte.TryParse(parts[3], out d))
                        continue;
                    if (!byte.TryParse(parts[4], out e))
                        continue;
                    if (e > 32)
                        continue;
                    uint ipnum = ((uint)a << 24) |
                        ((uint)b << 16) |
                        ((uint)c << 8) |
                        d;

                    uint mask = 0xffffffff;
                    mask <<= (32 - e);

                    uint ipstart = ipnum & mask;
                    uint ipend = ipnum | (mask ^ 0xffffffff);
                    _ranges.Add((ipstart, ipend));
                }
            }
            if (_config.Geo != null && _config.Geo.IsEnabled)
            {
                var mmFile = new FileInfo(Path.Combine(dnsServer.ApplicationFolder, "geo.mmdb"));

                if (mmFile.Exists)
                {
                    try
                    {
                        _geoDatabase = new DatabaseReader(mmFile.FullName, MaxMind.Db.FileAccessMode.MemoryMapped);
                        dnsServer.WriteLog("AntiBadDns: Load geo database successfully.");
                    }
                    catch
                    {
                        dnsServer.WriteLog("AntiBadDns: geo.mmdb is a bad file.");
                    }
                }
                if (_config.Geo.SubscribeUrl != null)
                {
                    _cts = new CancellationTokenSource();
                    _subscribeTask = Task.Run(SubscribeGeoDatabase);
                }
            }
            if (_config.NameServers != null && _config.NameServers.Count != 0)
            {
                List<NameServerAddress> servers = new List<NameServerAddress>();
                foreach (var item in _config.NameServers)
                {
                    if (!IPAddress.TryParse(item.Ip, out var address))
                    {
                        dnsServer.WriteLog($"AntiBadDns: NameServer parse ip address failed({item.Ip}).");
                        continue;
                    }
                    try
                    {
                        if (item.Url == null)
                        {
                            if (item.Port != 0)
                                servers.Add(new NameServerAddress(new IPEndPoint(address, item.Port), item.Protocol));
                            else
                                servers.Add(new NameServerAddress(address, item.Protocol));
                        }
                        else
                        {
                            switch (item.Protocol)
                            {
                                case DnsTransportProtocol.Https:
                                case DnsTransportProtocol.HttpsJson:
                                    if (Uri.TryCreate(item.Url, UriKind.Absolute, out var uri))
                                        servers.Add(new NameServerAddress(uri, address, item.Protocol));
                                    else
                                        dnsServer.WriteLog($"AntiBadDns: NameServere parse url failed({item.Url}).");
                                    break;
                                default:
                                    if (item.Port != 0)
                                        servers.Add(new NameServerAddress(item.Url, new IPEndPoint(address, item.Port), item.Protocol));
                                    else
                                        servers.Add(new NameServerAddress(item.Url, address, item.Protocol));
                                    break;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        dnsServer.WriteLog("AntiBadDns: Create NameServer failed.");
                        dnsServer.WriteLog(ex);
                    }
                }
                if (servers.Count != 0)
                {
                    _dnsClient = new DnsClient(servers);
                    if (_config.Proxy != null)
                    {
                        try
                        {
                            switch (_config.Proxy.Type)
                            {
                                case NetProxyType.Http:
                                    if (_config.Proxy.Username == null)
                                        _dnsClient.Proxy = NetProxy.CreateHttpProxy(_config.Proxy.Address, _config.Proxy.Port);
                                    else
                                        _dnsClient.Proxy = NetProxy.CreateHttpProxy(_config.Proxy.Address, _config.Proxy.Port, new NetworkCredential(_config.Proxy.Username, _config.Proxy.Password));
                                    break;
                                case NetProxyType.Socks5:
                                    if (_config.Proxy.Username == null)
                                        _dnsClient.Proxy = NetProxy.CreateSocksProxy(_config.Proxy.Address, _config.Proxy.Port);
                                    else
                                        _dnsClient.Proxy = NetProxy.CreateSocksProxy(_config.Proxy.Address, _config.Proxy.Port, new NetworkCredential(_config.Proxy.Username, _config.Proxy.Password));
                                    break;
                            }
                            dnsServer.WriteLog($"AntiBadDns: Proxy configured.");
                        }
                        catch (Exception ex)
                        {
                            dnsServer.WriteLog($"AntiBadDns: Proxy create failed.");
                            dnsServer.WriteLog(ex);
                        }
                    }
                    dnsServer.WriteLog($"AntiBadDns: NameServers configured.");
                }
                else
                    dnsServer.WriteLog($"AntiBadDns: There is no any NameServer.");

            }
            return Task.CompletedTask;
        }

        private async Task SubscribeGeoDatabase()
        {
            while (!_cts.IsCancellationRequested)
            {
                bool success = false;
                HttpClient client = new HttpClient();
                try
                {
                    _dnsServer.WriteLog("AntiBadDns: Starting download geo database.");
                    var stream = await client.GetStreamAsync(_config.Geo.SubscribeUrl);
                    var file = new MemoryStream();
                    await stream.CopyToAsync(file);
                    await stream.DisposeAsync();
                    file.Position = 0;
                    try
                    {
                        var database = new DatabaseReader(file);
                        await File.WriteAllBytesAsync(Path.Combine(_dnsServer.ApplicationFolder, "geo_new.mmdb"), file.ToArray());
                        _geoDatabase = database;
                        success = true;
                        _dnsServer.WriteLog("AntiBadDns: Download geo database successfully.");
                    }
                    catch
                    {
                        _dnsServer.WriteLog("AntiBadDns: Download geo database failed.");
                    }
                }
                catch
                {
                    _dnsServer.WriteLog("AntiBadDns: Download geo database failed.");
                }
                try
                {
                    if (success)
                    {
                        await Task.Delay(DateTime.Today.AddDays(1) - DateTime.Now, _cts.Token);
                    }
                    else
                    {
                        await Task.Delay(TimeSpan.FromMinutes(10), _cts.Token);
                    }
                }
                catch
                {

                }
            }
        }

        public async Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed)
        {
            if (_config.Debug)
                _dnsServer.WriteLog($"AntiBadDns: Incoming request({request.Question[0].Name}).");
                if (_dnsClient == null)
                    return await _dnsServer.DirectQueryAsync(request);
            bool useDefault = true;
            if (_config.Domains != null && _config.Domains.Count != 0)
            {
                DnsQuestionRecord question = request.Question[0];
                var name = question.Name;
                foreach (var domain in _config.Domains)
                {
                    if (domain.StartsWith("+."))
                    {
                        if (name.AsSpan().EndsWith(domain.AsSpan().Slice(2), StringComparison.OrdinalIgnoreCase))
                        {
                            useDefault = false;
                            _dnsServer.WriteLog($"AntiBadDns: Match domain({domain}).");
                            break;
                        }
                    }
                    else if (domain.StartsWith("*."))
                    {
                        var i = name.IndexOf(".");
                        if (i != -1)
                        {
                            if (name.AsSpan().Slice(i + 1).Equals(domain.AsSpan().Slice(2), StringComparison.OrdinalIgnoreCase))
                            {
                                _dnsServer.WriteLog($"AntiBadDns: Match domain({domain}).");
                                useDefault = false;
                                break;
                            }
                        }
                    }
                    else if (name == domain)
                    {
                        _dnsServer.WriteLog($"AntiBadDns: Match domain({domain}).");
                        useDefault = false;
                        break;
                    }
                    else
                    {
                        if (_config.Debug)
                            _dnsServer.WriteLog($"AntiBadDns: Domain not match({name}).");
                    }
                }
            }
            DnsDatagram result;
            if (useDefault)
            {
                bool resolveAgain = false;
                DnsQuestionRecord question = request.Question[0];

                result = await _dnsServer.DirectQueryAsync(request);
                switch (question.Type)
                {
                    case DnsResourceRecordType.A:
                        {
                            EDnsClientSubnetOptionData requestECS = result.GetEDnsClientSubnetOption();
                            if (requestECS is not null)
                            {
                                if (_ranges != null && _ranges.Count != 0)
                                {
                                    var bytes = requestECS.Address.GetAddressBytes();
                                    uint ipnum = ((uint)bytes[0] << 24) |
                                        ((uint)bytes[1] << 16) |
                                        ((uint)bytes[2] << 8) |
                                        bytes[3];
                                    foreach (var range in _ranges)
                                    {
                                        if (ipnum >= range.Item1 && ipnum <= range.Item2)
                                        {
                                            resolveAgain = true;
                                            _dnsServer.WriteLog($"AntiBadDns: Match ip range({requestECS.Address}).");
                                            break;
                                        }
                                    }
                                }
                                if (resolveAgain)
                                    break;
                                if (_config.Geo.Locations != null && _config.Geo.Locations.Count != 0 && _geoDatabase != null)
                                {
                                    if (!_geoDatabase.TryCountry(requestECS.Address, out CountryResponse response) || _config.Geo.Locations.Contains(response.Country.IsoCode))
                                    {
                                        if (response == null)
                                            _dnsServer.WriteLog($"AntiBadDns: Match location failed({requestECS.Address}).");
                                        else
                                            _dnsServer.WriteLog($"AntiBadDns: Match location({requestECS.Address}:{response.Country.IsoCode}).");
                                        resolveAgain = true;
                                    }
                                }
                            }
                            else
                            {
                                if (_config.Debug)
                                {
                                    _dnsServer.WriteLog($"AntiBadDns: First request failed, need reslove again.");
                                    _dnsServer.WriteLog(JsonSerializer.Serialize(result));
                                }
                                resolveAgain = true;
                            }
                            break;
                        }
                    case DnsResourceRecordType.AAAA:
                        {
                            EDnsClientSubnetOptionData requestECS = request.GetEDnsClientSubnetOption();
                            if (requestECS is not null)
                            {
                                if (_config.Geo.Locations != null && _config.Geo.Locations.Count != 0 && _geoDatabase != null)
                                {
                                    if (!_geoDatabase.TryCountry(requestECS.Address, out CountryResponse response) || _config.Geo.Locations.Contains(response.Country.IsoCode))
                                    {
                                        if (response == null)
                                            _dnsServer.WriteLog($"AntiBadDns: Match location failed({requestECS.Address}).");
                                        else
                                            _dnsServer.WriteLog($"AntiBadDns: Match location({requestECS.Address}:{response.Country.IsoCode}).");
                                        resolveAgain = true;
                                    }
                                }
                            }
                            else
                            {
                                resolveAgain = true;
                            }
                            break;
                        }
                }
                if (!resolveAgain)
                    return result;
                else
                {
                    if (_config.Debug)
                        _dnsServer.WriteLog($"AntiBadDns: Need resolve again({question.Name}).");
                }
            }

            return await _dnsClient.ResolveAsync(request);
        }
    }
}
