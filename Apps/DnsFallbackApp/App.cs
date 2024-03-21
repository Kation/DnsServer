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
    public class App : IDnsApplication, IDnsAuthoritativeRequestHandler, IDnsPostProcessor
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
            if (_geoDatabase != null)
            {
                _geoDatabase.Dispose();
                _geoDatabase = null;
            }
            _ranges = null;
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
                    ReadCommentHandling = JsonCommentHandling.Skip,
                    Converters =
                    {
                        new System.Text.Json.Serialization.JsonStringEnumConverter()
                    }
                });
            }
            catch (Exception ex)
            {
                dnsServer.WriteLog("DnsFallbackApp: Read config failed.");
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
                        dnsServer.WriteLog("DnsFallbackApp: Load geo database successfully.");
                    }
                    catch
                    {
                        dnsServer.WriteLog("DnsFallbackApp: geo.mmdb is a bad file.");
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
                        dnsServer.WriteLog($"DnsFallbackApp: Parse NameServer ip address failed({item.Ip}).");
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
                                    servers.Add(new NameServerAddress(item.Url, address, item.Protocol));
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
                        dnsServer.WriteLog("DnsFallbackApp: Create NameServer failed.");
                        dnsServer.WriteLog(ex);
                    }
                }
                if (servers.Count != 0)
                {
                    _dnsClient = new DnsClient(servers);
                    _dnsClient.Concurrency = 10;
                    _dnsClient.DnssecValidation = false;
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
                            dnsServer.WriteLog($"DnsFallbackApp: Proxy configured.");
                        }
                        catch (Exception ex)
                        {
                            dnsServer.WriteLog($"DnsFallbackApp: Proxy create failed.");
                            dnsServer.WriteLog(ex);
                        }
                    }
                    dnsServer.WriteLog($"DnsFallbackApp: NameServers configured.");
                }
                else
                    dnsServer.WriteLog($"DnsFallbackApp: There is no available NameServer.");

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
                    _dnsServer.WriteLog("DnsFallbackApp: Starting download geo database.");
                    var stream = await client.GetStreamAsync(_config.Geo.SubscribeUrl);
                    var file = new MemoryStream();
                    await stream.CopyToAsync(file);
                    await stream.DisposeAsync();
                    file.Position = 0;
                    if (_cts.IsCancellationRequested)
                        return;
                    try
                    {
                        var database = new DatabaseReader(file);
                        await File.WriteAllBytesAsync(Path.Combine(_dnsServer.ApplicationFolder, "geo_new.mmdb"), file.ToArray());
                        _geoDatabase = database;
                        success = true;
                        _dnsServer.WriteLog("DnsFallbackApp: Download geo database successfully.");
                    }
                    catch
                    {
                        _dnsServer.WriteLog("DnsFallbackApp: Download geo database failed.");
                    }
                }
                catch
                {
                    _dnsServer.WriteLog("DnsFallbackApp: Download geo database failed.");
                }
                if (_cts.IsCancellationRequested)
                    return;
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
            if (_config == null)
                return null;
            if (_config.IsDebug)
                _dnsServer.WriteLog($"DnsFallbackApp: Incoming request({request.Question[0].Name}).");
            if (_dnsClient == null)
                return null;
            bool useDefault = true;
            if (_config.Domains != null && _config.Domains.Count != 0)
            {
                DnsQuestionRecord question = request.Question[0];
                var name = question.Name;
                foreach (var domain in _config.Domains)
                {
                    if (domain.StartsWith("+."))
                    {
                        if (name.AsSpan().EndsWith(domain.AsSpan().Slice(1), StringComparison.OrdinalIgnoreCase) || name.AsSpan().Equals(domain.AsSpan().Slice(2), StringComparison.OrdinalIgnoreCase))
                        {
                            useDefault = false;
                            if (_config.IsDebug)
                                _dnsServer.WriteLog($"DnsFallbackApp: Match domain({domain}), fallback.");
                            break;
                        }
                    }
                    else if (domain.StartsWith("*."))
                    {
                        var i = name.IndexOf(".");
                        if (i != -1)
                        {
                            if (name.AsSpan().Slice(i + 1).Equals(domain.AsSpan().Slice(2), StringComparison.OrdinalIgnoreCase) || name.AsSpan().Equals(domain.AsSpan().Slice(2), StringComparison.OrdinalIgnoreCase))
                            {
                                if (_config.IsDebug)
                                    _dnsServer.WriteLog($"DnsFallbackApp: Match domain({domain}), fallback.");
                                useDefault = false;
                                break;
                            }
                        }
                    }
                    else if (name == domain)
                    {
                        if (_config.IsDebug)
                            _dnsServer.WriteLog($"DnsFallbackApp: Match domain({domain}), fallback.");
                        useDefault = false;
                        break;
                    }
                    else
                    {
                        if (_config.IsDebug)
                            _dnsServer.WriteLog($"DnsFallbackApp: Domain not match({name}).");
                    }
                }
            }
            if (useDefault)
                return null;
            var result = _dnsServer.DnsCache.Query(request);
            if (result != null)
            {
                result.Tag = DnsServerResponseType.Cached;
                return result;
            }
            result = await _dnsClient.ResolveAsync(request);
            _dnsServer.DnsCache.CacheResponse(result);
            return result;
        }

        public async Task<DnsDatagram> PostProcessAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
        {
            if (_config == null)
                return response;
            if (response.Tag is DnsServerResponseType type && type == DnsServerResponseType.Cached && response.Answer.Count != 0)
            {
                if (_config.IsDebug)
                    _dnsServer.WriteLog($"DnsFallbackApp: Cache response({request.Question[0].Name}).");
                return response;
            }
            if (response.AuthoritativeAnswer)
            {
                if (_config.IsDebug)
                    _dnsServer.WriteLog($"DnsFallbackApp: Upper app response({request.Question[0].Name}).");
                return response;
            }
            if (_config.ExceptDomains != null && _config.ExceptDomains.Any(t => t == request.Question[0].Name || request.Question[0].Name.EndsWith("." + t)))
            {
                if (_config.IsDebug)
                    _dnsServer.WriteLog($"DnsFallbackApp: Skip except domain({request.Question[0].Name}).");
                return response;
            }
            if (_config.IsDebug)
                _dnsServer.WriteLog($"DnsFallbackApp: Request response({request.Question[0].Name}).");
            bool resolveAgain = false;
            if (response.RCODE != DnsResponseCode.NoError)
            {
                if (_config.IsDebug)
                    _dnsServer.WriteLog($"DnsFallbackApp: Response error({response.RCODE}), fallback.");
                resolveAgain = true;
            }
            else if (response.Answer.Count == 0)
            {
                if (_config.IsDebug)
                    _dnsServer.WriteLog($"DnsFallbackApp: Response with empty record, fallback.");
                resolveAgain = true;
            }
            if (!resolveAgain)
            {
                foreach (var answer in response.Answer)
                {
                    switch (answer.Type)
                    {
                        case DnsResourceRecordType.A:
                            {
                                var ipAddress = ((DnsARecordData)answer.RDATA).Address;
                                if (_config.IsDebug)
                                    _dnsServer.WriteLog($"DnsFallbackApp: {response.Question[0].Name} - {ipAddress}");
                                if (_ranges != null && _ranges.Count != 0)
                                {
                                    var bytes = ipAddress.GetAddressBytes();
                                    uint ipnum = ((uint)bytes[0] << 24) |
                                    ((uint)bytes[1] << 16) |
                                    ((uint)bytes[2] << 8) |
                                    bytes[3];
                                    foreach (var range in _ranges)
                                    {
                                        if (ipnum >= range.Item1 && ipnum <= range.Item2)
                                        {
                                            resolveAgain = true;
                                            if (_config.IsDebug)
                                                _dnsServer.WriteLog($"DnsFallbackApp: Match ip range.({ipAddress}), fallback.");
                                            break;
                                        }
                                    }
                                }
                                if (resolveAgain)
                                    break;
                                if (_config.Geo.IsEnabled && _config.Geo.Countries != null && _config.Geo.Countries.Count != 0 && _geoDatabase != null)
                                {
                                    if (_geoDatabase.TryCountry(ipAddress, out CountryResponse countryResponse))
                                    {
                                        if (_config.Geo.Countries.Contains(countryResponse.Country.IsoCode))
                                        {
                                            if (_config.IsDebug)
                                                _dnsServer.WriteLog($"DnsFallbackApp: Match country({ipAddress}:{countryResponse.Country.IsoCode}).");
                                        }
                                        else
                                        {
                                            if (_config.IsDebug)
                                                _dnsServer.WriteLog($"DnsFallbackApp: Not match country({ipAddress}:{countryResponse.Country.IsoCode}), fallback.");
                                            resolveAgain = true;
                                        }
                                    }
                                    else
                                    {
                                        if (_config.IsDebug)
                                            _dnsServer.WriteLog($"DnsFallbackApp: Match country failed({ipAddress}), fallback.");
                                        resolveAgain = true;
                                    }
                                }
                                break;
                            }
                        case DnsResourceRecordType.AAAA:
                            {
                                if (_config.Geo.IsEnabled && _config.Geo.Countries != null && _config.Geo.Countries.Count != 0 && _geoDatabase != null)
                                {
                                    var ipAddress = ((DnsAAAARecordData)answer.RDATA).Address;
                                    if (_config.IsDebug)
                                        _dnsServer.WriteLog($"DnsFallbackApp: {response.Question[0].Name} - {ipAddress}");
                                    if (_geoDatabase.TryCountry(ipAddress, out CountryResponse countryResponse))
                                    {
                                        if (_config.Geo.Countries.Contains(countryResponse.Country.IsoCode))
                                        {
                                            if (_config.IsDebug)
                                                _dnsServer.WriteLog($"DnsFallbackApp: Match country({ipAddress}:{countryResponse.Country.IsoCode}).");
                                        }
                                        else
                                        {
                                            if (_config.IsDebug)
                                                _dnsServer.WriteLog($"DnsFallbackApp: Not match country, fallback.({ipAddress}:{countryResponse.Country.IsoCode}).");
                                            resolveAgain = true;
                                        }
                                    }
                                    else
                                    {
                                        if (_config.IsDebug)
                                            _dnsServer.WriteLog($"DnsFallbackApp: Match country failed({ipAddress}).");
                                        resolveAgain = true;
                                    }
                                }
                                break;
                            }
                    }
                    if (resolveAgain)
                        break;
                }
            }
            if (resolveAgain)
            {
                if (_config.IsDebug)
                    _dnsServer.WriteLog($"DnsFallbackApp: Fallback, resolve again({request.Question[0].Name}).");
                DnsDatagram result;
                try
                {
                    result = await _dnsClient.ResolveAsync(request);
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog($"DnsFallbackApp: Fallback resolve failed. " + ex.Message);
                    return response;
                }
                if (result.RCODE == DnsResponseCode.NoError)
                    _dnsServer.DnsCache.CacheResponse(result);
                return result;
            }
            return response;
        }
    }
}
