using Microsoft.Win32;
using System.Runtime.Versioning;
using SentinelAC.Core.Interfaces;
using SentinelAC.Core.Models;

namespace SentinelAC.Detectors
{
    [SupportedOSPlatform("windows")]
    public sealed class SystemManipulationDetector : IDetector
    {
        public DetectionType Type => DetectionType.SystemManipulation;
        public bool RequiresAdminRights => false;

        public async Task<List<DetectionResult>> ScanAsync()
        {
            return await Task.Run(() =>
            {
                List<DetectionResult> results = [];

                CheckSystemTimeManipulation(results);
                CheckDPIManipulation(results);
                CheckDebugPrivileges(results);

                return results;
            });
        }

        private static void CheckSystemTimeManipulation(List<DetectionResult> results)
        {
            try
            {
                DateTime systemTime = DateTime.Now;
                DateTime utcTime = DateTime.UtcNow;

                TimeSpan offset = systemTime - utcTime;
                double expectedOffset = TimeZoneInfo.Local.GetUtcOffset(systemTime).TotalHours;
                double actualOffset = offset.TotalHours;

                if (Math.Abs(actualOffset - expectedOffset) > 1.0)
                {
                    results.Add(new DetectionResult
                    {
                        Type = DetectionType.SystemManipulation,
                        Level = ThreatLevel.Medium,
                        Description = "System time manipulation detected",
                        Details = $"Time offset anomaly detected (Expected: {expectedOffset:F2}h, Actual: {actualOffset:F2}h)",
                        Metadata = new Dictionary<string, string>
                        {
                            ["SystemTime"] = systemTime.ToString("yyyy-MM-dd HH:mm:ss"),
                            ["UTCTime"] = utcTime.ToString("yyyy-MM-dd HH:mm:ss"),
                            ["ExpectedOffset"] = expectedOffset.ToString("F2"),
                            ["ActualOffset"] = actualOffset.ToString("F2")
                        }
                    });
                }
            }
            catch
            {
            }
        }

        private static void CheckDPIManipulation(List<DetectionResult> results)
        {
            try
            {
                using RegistryKey? key = Registry.CurrentUser.OpenSubKey(@"Control Panel\Desktop");
                if (key != null)
                {
                    object? dpiScaling = key.GetValue("Win8DpiScaling");
                    object? logPixels = key.GetValue("LogPixels");

                    if (logPixels != null && int.TryParse(logPixels.ToString(), out int dpi))
                    {
                        if (dpi != 96 && dpi != 120 && dpi != 144)
                        {
                            results.Add(new DetectionResult
                            {
                                Type = DetectionType.SystemManipulation,
                                Level = ThreatLevel.Low,
                                Description = "Non-standard DPI scaling detected",
                                Details = $"Custom DPI value: {dpi} (Standard: 96, 120, 144)",
                                Metadata = new Dictionary<string, string>
                                {
                                    ["DPI"] = dpi.ToString(),
                                    ["Type"] = "CustomDPI"
                                }
                            });
                        }
                    }
                }
            }
            catch
            {
            }
        }

        private static void CheckDebugPrivileges(List<DetectionResult> results)
        {
            try
            {
                using RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug");
                if (key != null)
                {
                    object? debugger = key.GetValue("Debugger");
                    object? auto = key.GetValue("Auto");

                    if (debugger != null && auto != null && auto.ToString() == "1")
                    {
                        results.Add(new DetectionResult
                        {
                            Type = DetectionType.SystemManipulation,
                            Level = ThreatLevel.Medium,
                            Description = "Automatic debugging enabled",
                            Details = $"System configured for automatic crash debugging: {debugger}",
                            Metadata = new Dictionary<string, string>
                            {
                                ["Debugger"] = debugger.ToString() ?? "Unknown",
                                ["AutoDebug"] = "Enabled"
                            }
                        });
                    }
                }
            }
            catch
            {
            }
        }
    }
}