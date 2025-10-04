using SentinelAC.Core.Data;
using SentinelAC.Core.Interfaces;
using SentinelAC.Core.Models;
using System.Runtime.Versioning;
using System.ServiceProcess;

namespace SentinelAC.Detectors
{
    [SupportedOSPlatform("windows")]
    public sealed class DriverDetector : IDetector
    {
        private readonly ISignatureDatabase _signatureDatabase;
        private readonly WhitelistDatabase _whitelistDatabase;

        public DetectionType Type => DetectionType.Driver;
        public bool RequiresAdminRights => true;

        public DriverDetector(ISignatureDatabase signatureDatabase, WhitelistDatabase whitelistDatabase)
        {
            _signatureDatabase = signatureDatabase;
            _whitelistDatabase = whitelistDatabase;
        }

        public async Task<List<DetectionResult>> ScanAsync()
        {
            return await Task.Run(() =>
            {
                List<DetectionResult> results = [];

                try
                {
                    ServiceController[] drivers = ServiceController.GetDevices();

                    foreach (ServiceController driver in drivers)
                    {
                        try
                        {
                            DetectionResult? result = AnalyzeDriver(driver);
                            if (result != null)
                            {
                                results.Add(result);
                            }
                        }
                        catch
                        {
                        }
                        finally
                        {
                            driver.Dispose();
                        }
                    }
                }
                catch
                {
                }

                return results;
            });
        }

        private DetectionResult? AnalyzeDriver(ServiceController driver)
        {
            string driverName = driver.ServiceName.ToLowerInvariant();

            if (_whitelistDatabase.IsTrustedService(driverName))
                return null;

            if (_signatureDatabase.IsKnownThreat(driverName))
            {
                return new DetectionResult
                {
                    Type = DetectionType.Driver,
                    Level = ThreatLevel.Critical,
                    Description = $"Known malicious driver detected: {driver.ServiceName}",
                    Details = $"Driver Status: {driver.Status}, Display Name: {driver.DisplayName}",
                    Metadata = new Dictionary<string, string>
                    {
                        ["DriverName"] = driver.ServiceName,
                        ["DisplayName"] = driver.DisplayName,
                        ["Status"] = driver.Status.ToString()
                    }
                };
            }

            if (_signatureDatabase.IsSuspiciousPattern(driverName))
            {
                return new DetectionResult
                {
                    Type = DetectionType.Driver,
                    Level = ThreatLevel.High,
                    Description = $"Suspicious driver detected: {driver.ServiceName}",
                    Details = $"Driver Status: {driver.Status}, Display Name: {driver.DisplayName}",
                    Metadata = new Dictionary<string, string>
                    {
                        ["DriverName"] = driver.ServiceName,
                        ["DisplayName"] = driver.DisplayName,
                        ["Status"] = driver.Status.ToString()
                    }
                };
            }

            if (IsMemoryAccessDriver(driverName))
            {
                return new DetectionResult
                {
                    Type = DetectionType.Driver,
                    Level = ThreatLevel.High,
                    Description = $"Memory access driver detected: {driver.ServiceName}",
                    Details = $"Potential kernel-level memory manipulation driver",
                    Metadata = new Dictionary<string, string>
                    {
                        ["DriverName"] = driver.ServiceName,
                        ["DisplayName"] = driver.DisplayName,
                        ["Status"] = driver.Status.ToString()
                    }
                };
            }

            return null;
        }

        private static bool IsMemoryAccessDriver(string driverName)
        {
            string[] memoryDrivers = ["kernelmemory", "physmem", "memaccess", "rweverything", "pcileech"];
            return memoryDrivers.Any(d => driverName.Contains(d));
        }
    }
}