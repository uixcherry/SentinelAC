using Microsoft.Win32;
using SentinelAC.Core.Interfaces;
using SentinelAC.Core.Models;
using System.Runtime.Versioning;

namespace SentinelAC.Detectors
{
    [SupportedOSPlatform("windows")]
    public sealed class RegistryCleanerDetector : IDetector
    {
        public DetectionType Type => DetectionType.Registry;
        public bool RequiresAdminRights => false;

        private readonly string[] _suspiciousCleanerPatterns =
        [
            "ccleaner", "cleanmgr", "regcleaner", "wisecleaner",
            "glary", "privazer", "bleachbit", "eraser"
        ];

        public async Task<List<DetectionResult>> ScanAsync()
        {
            return await Task.Run(() =>
            {
                List<DetectionResult> results = [];

                CheckRunMRUCleaning(results);
                CheckTypedPathsCleaning(results);
                CheckRecentDocsCleaning(results);
                CheckMuiCacheCleaning(results);
                CheckUserAssistCleaning(results);

                return results;
            });
        }

        private void CheckRunMRUCleaning(List<DetectionResult> results)
        {
            try
            {
                using RegistryKey? runMruKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU");

                if (runMruKey == null)
                {
                    results.Add(new DetectionResult
                    {
                        Type = DetectionType.Registry,
                        Level = ThreatLevel.High,
                        Description = "Run dialog history (RunMRU) completely missing",
                        Details = "Registry key deleted - typical anti-forensics behavior",
                        ConfidenceScore = 0.85,
                        Metadata = new Dictionary<string, string>
                        {
                            ["KeyPath"] = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
                            ["Status"] = "Missing",
                            ["Severity"] = "Suspicious"
                        }
                    });
                    return;
                }

                string[] valueNames = runMruKey.GetValueNames();

                if (valueNames.Length <= 1)
                {
                    results.Add(new DetectionResult
                    {
                        Type = DetectionType.Registry,
                        Level = ThreatLevel.Medium,
                        Description = "Run dialog history suspiciously empty",
                        Details = $"Only {valueNames.Length} entries found - possible cleaning",
                        ConfidenceScore = 0.70,
                        Metadata = new Dictionary<string, string>
                        {
                            ["KeyPath"] = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
                            ["EntryCount"] = valueNames.Length.ToString(),
                            ["Expected"] = "Multiple entries on normal system"
                        }
                    });
                }
            }
            catch
            {
            }
        }

        private void CheckTypedPathsCleaning(List<DetectionResult> results)
        {
            try
            {
                using RegistryKey? typedPathsKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths");

                if (typedPathsKey == null)
                {
                    results.Add(new DetectionResult
                    {
                        Type = DetectionType.Registry,
                        Level = ThreatLevel.Medium,
                        Description = "Explorer typed paths history missing",
                        Details = "TypedPaths registry key deleted",
                        ConfidenceScore = 0.75,
                        Metadata = new Dictionary<string, string>
                        {
                            ["KeyPath"] = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
                            ["Status"] = "Missing"
                        }
                    });
                }
            }
            catch
            {
            }
        }

        private void CheckRecentDocsCleaning(List<DetectionResult> results)
        {
            try
            {
                using RegistryKey? recentDocsKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs");

                if (recentDocsKey != null)
                {
                    string[] subKeyNames = recentDocsKey.GetSubKeyNames();
                    string[] valueNames = recentDocsKey.GetValueNames();

                    if (subKeyNames.Length == 0 && valueNames.Length <= 1)
                    {
                        results.Add(new DetectionResult
                        {
                            Type = DetectionType.Registry,
                            Level = ThreatLevel.Medium,
                            Description = "Recent documents history suspiciously empty",
                            Details = "RecentDocs cleared - possible privacy tool usage",
                            ConfidenceScore = 0.65,
                            Metadata = new Dictionary<string, string>
                            {
                                ["KeyPath"] = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
                                ["SubKeys"] = subKeyNames.Length.ToString(),
                                ["Values"] = valueNames.Length.ToString()
                            }
                        });
                    }
                }
            }
            catch
            {
            }
        }

        private void CheckMuiCacheCleaning(List<DetectionResult> results)
        {
            try
            {
                using RegistryKey? muiCacheKey = Registry.CurrentUser.OpenSubKey(@"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache");

                if (muiCacheKey == null)
                {
                    results.Add(new DetectionResult
                    {
                        Type = DetectionType.Registry,
                        Level = ThreatLevel.High,
                        Description = "MUICache deleted - application execution history removed",
                        Details = "This key tracks executed programs - deletion is suspicious",
                        ConfidenceScore = 0.80,
                        Metadata = new Dictionary<string, string>
                        {
                            ["KeyPath"] = @"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                            ["Status"] = "Missing",
                            ["Purpose"] = "Tracks executed applications"
                        }
                    });
                }
            }
            catch
            {
            }
        }

        private void CheckUserAssistCleaning(List<DetectionResult> results)
        {
            try
            {
                using RegistryKey? userAssistKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");

                if (userAssistKey == null)
                {
                    results.Add(new DetectionResult
                    {
                        Type = DetectionType.Registry,
                        Level = ThreatLevel.Critical,
                        Description = "UserAssist key deleted - execution tracking removed",
                        Details = "UserAssist tracks all program executions - deletion indicates anti-forensics",
                        ConfidenceScore = 0.90,
                        Metadata = new Dictionary<string, string>
                        {
                            ["KeyPath"] = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
                            ["Status"] = "Missing",
                            ["Severity"] = "Critical - Strong indicator of cheat cleanup"
                        }
                    });
                    return;
                }

                string[] guidKeys = userAssistKey.GetSubKeyNames();
                if (guidKeys.Length == 0)
                {
                    results.Add(new DetectionResult
                    {
                        Type = DetectionType.Registry,
                        Level = ThreatLevel.High,
                        Description = "UserAssist subkeys empty - execution history cleared",
                        Details = "All UserAssist GUID subkeys removed",
                        ConfidenceScore = 0.85,
                        Metadata = new Dictionary<string, string>
                        {
                            ["KeyPath"] = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
                            ["SubKeyCount"] = "0",
                            ["Expected"] = "At least 2 GUID subkeys"
                        }
                    });
                }
            }
            catch
            {
            }
        }
    }
}
