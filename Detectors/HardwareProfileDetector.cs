using System.Management;
using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using SentinelAC.Core.Interfaces;
using SentinelAC.Core.Models;

namespace SentinelAC.Detectors
{
    [SupportedOSPlatform("windows")]
    public sealed class HardwareProfileDetector : IDetector
    {
        public DetectionType Type => DetectionType.HardwareProfile;
        public bool RequiresAdminRights => false;

        public async Task<List<DetectionResult>> ScanAsync()
        {
            return await Task.Run(() =>
            {
                List<DetectionResult> results = [];

                Dictionary<string, string> hwInfo = CollectHardwareInfo();
                string hwid = GenerateHWID(hwInfo);

                results.Add(new DetectionResult
                {
                    Type = DetectionType.HardwareProfile,
                    Level = ThreatLevel.None,
                    Description = "Hardware Profile Information",
                    Details = $"HWID: {hwid}",
                    Metadata = hwInfo
                });

                return results;
            });
        }

        private static Dictionary<string, string> CollectHardwareInfo()
        {
            Dictionary<string, string> info = new()
            {
                ["HWID"] = string.Empty,
                ["ProcessorID"] = GetProcessorId(),
                ["MotherboardSerial"] = GetMotherboardSerial(),
                ["BIOSSerial"] = GetBIOSSerial(),
                ["MACAddresses"] = GetMACAddresses(),
                ["DiskSerials"] = GetDiskSerials(),
                ["VideoControllerID"] = GetVideoControllerId(),
                ["OSInstallDate"] = GetOSInstallDate()
            };

            return info;
        }

        private static string GenerateHWID(Dictionary<string, string> hwInfo)
        {
            StringBuilder sb = new();
            sb.Append(hwInfo["ProcessorID"]);
            sb.Append(hwInfo["MotherboardSerial"]);
            sb.Append(hwInfo["BIOSSerial"]);
            sb.Append(hwInfo["MACAddresses"]);

            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString()));
            return Convert.ToHexString(hash);
        }

        private static string GetProcessorId()
        {
            try
            {
                using ManagementObjectSearcher searcher = new("SELECT ProcessorId FROM Win32_Processor");
                foreach (ManagementObject obj in searcher.Get())
                {
                    return obj["ProcessorId"]?.ToString() ?? "Unknown";
                }
            }
            catch
            {
            }
            return "Unknown";
        }

        private static string GetMotherboardSerial()
        {
            try
            {
                using ManagementObjectSearcher searcher = new("SELECT SerialNumber FROM Win32_BaseBoard");
                foreach (ManagementObject obj in searcher.Get())
                {
                    return obj["SerialNumber"]?.ToString() ?? "Unknown";
                }
            }
            catch
            {
            }
            return "Unknown";
        }

        private static string GetBIOSSerial()
        {
            try
            {
                using ManagementObjectSearcher searcher = new("SELECT SerialNumber FROM Win32_BIOS");
                foreach (ManagementObject obj in searcher.Get())
                {
                    return obj["SerialNumber"]?.ToString() ?? "Unknown";
                }
            }
            catch
            {
            }
            return "Unknown";
        }

        private static string GetMACAddresses()
        {
            try
            {
                List<string> macAddresses = [];
                NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();

                foreach (NetworkInterface ni in interfaces)
                {
                    if (ni.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                        ni.OperationalStatus == OperationalStatus.Up)
                    {
                        string mac = ni.GetPhysicalAddress().ToString();
                        if (!string.IsNullOrEmpty(mac))
                        {
                            macAddresses.Add(mac);
                        }
                    }
                }

                return string.Join(",", macAddresses.Distinct());
            }
            catch
            {
            }
            return "Unknown";
        }

        private static string GetDiskSerials()
        {
            try
            {
                List<string> serials = [];
                using ManagementObjectSearcher searcher = new("SELECT SerialNumber FROM Win32_PhysicalMedia");

                foreach (ManagementObject obj in searcher.Get())
                {
                    string serial = obj["SerialNumber"]?.ToString()?.Trim() ?? string.Empty;
                    if (!string.IsNullOrEmpty(serial))
                    {
                        serials.Add(serial);
                    }
                }

                return string.Join(",", serials);
            }
            catch
            {
            }
            return "Unknown";
        }

        private static string GetVideoControllerId()
        {
            try
            {
                using ManagementObjectSearcher searcher = new("SELECT PNPDeviceID FROM Win32_VideoController");
                foreach (ManagementObject obj in searcher.Get())
                {
                    return obj["PNPDeviceID"]?.ToString() ?? "Unknown";
                }
            }
            catch
            {
            }
            return "Unknown";
        }

        private static string GetOSInstallDate()
        {
            try
            {
                using ManagementObjectSearcher searcher = new("SELECT InstallDate FROM Win32_OperatingSystem");
                foreach (ManagementObject obj in searcher.Get())
                {
                    string installDate = obj["InstallDate"]?.ToString() ?? string.Empty;
                    if (!string.IsNullOrEmpty(installDate))
                    {
                        DateTime dt = ManagementDateTimeConverter.ToDateTime(installDate);
                        return dt.ToString("yyyy-MM-dd HH:mm:ss");
                    }
                }
            }
            catch
            {
            }
            return "Unknown";
        }
    }
}