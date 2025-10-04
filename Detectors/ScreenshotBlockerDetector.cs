using System.Diagnostics;
using System.Runtime.Versioning;
using SentinelAC.Core.Interfaces;
using SentinelAC.Core.Models;

namespace SentinelAC.Detectors
{
    [SupportedOSPlatform("windows")]
    public sealed class ScreenshotBlockerDetector : IDetector
    {
        public DetectionType Type => DetectionType.ScreenshotBlocker;
        public bool RequiresAdminRights => false;

        public async Task<List<DetectionResult>> ScanAsync()
        {
            return await Task.Run(() =>
            {
                List<DetectionResult> results = [];

                CheckForScreenshotBlockers(results);
                CheckForOverlaySoftware(results);

                return results;
            });
        }

        private static void CheckForScreenshotBlockers(List<DetectionResult> results)
        {
            string[] blockerPatterns =
            [
                "screenshot blocker", "anti-screenshot", "screenprivacy",
                "obscure", "displayfusion", "ultramon"
            ];

            Process[] processes = Process.GetProcesses();
            foreach (Process process in processes)
            {
                try
                {
                    string processName = process.ProcessName.ToLowerInvariant();

                    if (blockerPatterns.Any(pattern => processName.Contains(pattern)))
                    {
                        results.Add(new DetectionResult
                        {
                            Type = DetectionType.ScreenshotBlocker,
                            Level = ThreatLevel.High,
                            Description = $"Screenshot blocking software detected: {process.ProcessName}",
                            Details = $"Process ID: {process.Id}",
                            Metadata = new Dictionary<string, string>
                            {
                                ["ProcessName"] = process.ProcessName,
                                ["ProcessId"] = process.Id.ToString()
                            }
                        });
                    }
                }
                catch
                {
                }
                finally
                {
                    process.Dispose();
                }
            }
        }

        private static void CheckForOverlaySoftware(List<DetectionResult> results)
        {
            string[] overlayPatterns =
            [
                "reshade", "rivatuner", "rtss", "msi afterburner",
                "nvidia overlay", "discord overlay", "steam overlay"
            ];

            Process[] processes = Process.GetProcesses();
            foreach (Process process in processes)
            {
                try
                {
                    string processName = process.ProcessName.ToLowerInvariant();

                    if (overlayPatterns.Any(pattern => processName.Contains(pattern)))
                    {
                        results.Add(new DetectionResult
                        {
                            Type = DetectionType.ScreenshotBlocker,
                            Level = ThreatLevel.Low,
                            Description = $"Overlay software detected: {process.ProcessName}",
                            Details = $"Process ID: {process.Id} (Can interfere with anti-cheat screenshots)",
                            Metadata = new Dictionary<string, string>
                            {
                                ["ProcessName"] = process.ProcessName,
                                ["ProcessId"] = process.Id.ToString(),
                                ["Type"] = "Overlay"
                            }
                        });
                    }
                }
                catch
                {
                }
                finally
                {
                    process.Dispose();
                }
            }
        }
    }
}