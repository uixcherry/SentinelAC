using System.Net;
using System.Net.NetworkInformation;
using SentinelAC.Core.Interfaces;
using SentinelAC.Core.Models;

namespace SentinelAC.Detectors
{
    public sealed class NetworkDetector : IDetector
    {
        public DetectionType Type => DetectionType.Network;
        public bool RequiresAdminRights => false;

        public async Task<List<DetectionResult>> ScanAsync()
        {
            return await Task.Run(() =>
            {
                List<DetectionResult> results = [];

                IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
                TcpConnectionInformation[] connections = properties.GetActiveTcpConnections();

                Dictionary<IPAddress, int> connectionCounts = [];

                foreach (TcpConnectionInformation connection in connections)
                {
                    IPAddress remoteIp = connection.RemoteEndPoint.Address;

                    if (IsLocalOrPrivateIP(remoteIp))
                        continue;

                    if (!connectionCounts.TryGetValue(remoteIp, out int value))
                    {
                        value = 0;
                        connectionCounts[remoteIp] = value;
                    }
                    connectionCounts[remoteIp] = ++value;

                    if (IsSuspiciousPort(connection.RemoteEndPoint.Port))
                    {
                        results.Add(new DetectionResult
                        {
                            Type = DetectionType.Network,
                            Level = ThreatLevel.Medium,
                            Description = $"Suspicious port connection detected",
                            Details = $"Remote: {connection.RemoteEndPoint}, Local: {connection.LocalEndPoint}, State: {connection.State}",
                            Metadata = new Dictionary<string, string>
                            {
                                ["RemoteAddress"] = remoteIp.ToString(),
                                ["RemotePort"] = connection.RemoteEndPoint.Port.ToString(),
                                ["LocalPort"] = connection.LocalEndPoint.Port.ToString(),
                                ["State"] = connection.State.ToString()
                            }
                        });
                    }
                }

                foreach (KeyValuePair<IPAddress, int> entry in connectionCounts)
                {
                    if (entry.Value > 100)
                    {
                        results.Add(new DetectionResult
                        {
                            Type = DetectionType.Network,
                            Level = ThreatLevel.High,
                            Description = $"Excessive connections to single IP detected",
                            Details = $"IP: {entry.Key}, Connection Count: {entry.Value}",
                            Metadata = new Dictionary<string, string>
                            {
                                ["IPAddress"] = entry.Key.ToString(),
                                ["ConnectionCount"] = entry.Value.ToString()
                            }
                        });
                    }
                }

                DetectionResult? vpnResult = CheckForVPN();
                if (vpnResult != null)
                {
                    results.Add(vpnResult);
                }

                return results;
            });
        }

        private static bool IsLocalOrPrivateIP(IPAddress ip)
        {
            if (IPAddress.IsLoopback(ip))
                return true;

            byte[] bytes = ip.GetAddressBytes();

            if (bytes.Length == 4)
            {
                return bytes[0] == 10 ||
                       (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                       (bytes[0] == 192 && bytes[1] == 168);
            }

            return false;
        }

        private static bool IsSuspiciousPort(int port)
        {
            int[] suspiciousPorts = [4444, 5555, 6666, 7777, 31337, 12345, 54321];
            return suspiciousPorts.Contains(port);
        }

        private static DetectionResult? CheckForVPN()
        {
            NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();

            foreach (NetworkInterface iface in interfaces)
            {
                string name = iface.Name.ToLowerInvariant();
                string description = iface.Description.ToLowerInvariant();

                if ((name.Contains("vpn") || name.Contains("tap") || name.Contains("tun") ||
                     description.Contains("vpn") || description.Contains("tap") || description.Contains("tun")) &&
                    iface.OperationalStatus == OperationalStatus.Up)
                {
                    return new DetectionResult
                    {
                        Type = DetectionType.Network,
                        Level = ThreatLevel.Low,
                        Description = $"VPN/Proxy adapter detected: {iface.Name}",
                        Details = $"Description: {iface.Description}, Status: {iface.OperationalStatus}",
                        Metadata = new Dictionary<string, string>
                        {
                            ["InterfaceName"] = iface.Name,
                            ["Description"] = iface.Description,
                            ["Status"] = iface.OperationalStatus.ToString()
                        }
                    };
                }
            }

            return null;
        }
    }
}