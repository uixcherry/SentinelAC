using Microsoft.Win32;
using SentinelAC.Core.Data;
using SentinelAC.Core.Interfaces;
using SentinelAC.Core.Models;
using System.Runtime.Versioning;

namespace SentinelAC.Detectors
{
    [SupportedOSPlatform("windows")]
    public sealed class RegistryDetector : IDetector
    {
        private readonly ISignatureDatabase _signatureDatabase;
        private readonly WhitelistDatabase _whitelistDatabase;

        public DetectionType Type => DetectionType.Registry;
        public bool RequiresAdminRights => false;

        public RegistryDetector(ISignatureDatabase signatureDatabase, WhitelistDatabase whitelistDatabase)
        {
            _signatureDatabase = signatureDatabase;
            _whitelistDatabase = whitelistDatabase;
        }

        public async Task<List<DetectionResult>> ScanAsync()
        {
            return await Task.Run(() =>
            {
                List<DetectionResult> results = [];

                string[] autostartPaths =
                [
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                    @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                    @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
                ];

                foreach (string path in autostartPaths)
                {
                    List<DetectionResult> autostartResults = ScanRegistryKey(Registry.LocalMachine, path, "HKLM");
                    results.AddRange(autostartResults);

                    List<DetectionResult> userAutostartResults = ScanRegistryKey(Registry.CurrentUser, path, "HKCU");
                    results.AddRange(userAutostartResults);
                }

                string[] suspiciousKeyPaths =
                [
                    @"SOFTWARE\Classes\CLSID",
                    @"SYSTEM\CurrentControlSet\Services"
                ];

                foreach (string path in suspiciousKeyPaths)
                {
                    List<DetectionResult> suspiciousResults = ScanForSuspiciousKeys(Registry.LocalMachine, path);
                    results.AddRange(suspiciousResults);
                }

                return results;
            });
        }

        private List<DetectionResult> ScanRegistryKey(RegistryKey root, string path, string rootName)
        {
            List<DetectionResult> results = [];

            try
            {
                using RegistryKey? key = root.OpenSubKey(path);
                if (key == null)
                    return results;

                string[] valueNames = key.GetValueNames();

                foreach (string valueName in valueNames)
                {
                    try
                    {
                        object? value = key.GetValue(valueName);
                        if (value == null)
                            continue;

                        string valueStr = value.ToString() ?? string.Empty;
                        string valueStrLower = valueStr.ToLowerInvariant();

                        if (_whitelistDatabase.IsTrustedPath(valueStrLower))
                            continue;

                        if (_signatureDatabase.IsKnownThreat(valueName.ToLowerInvariant()) ||
                            _signatureDatabase.IsSuspiciousPattern(valueName.ToLowerInvariant()) ||
                            _signatureDatabase.IsSuspiciousPattern(valueStrLower))
                        {
                            results.Add(new DetectionResult
                            {
                                Type = DetectionType.Registry,
                                Level = ThreatLevel.High,
                                Description = $"Suspicious autostart entry detected",
                                Details = $"Key: {rootName}\\{path}\\{valueName}, Value: {valueStr}",
                                Metadata = new Dictionary<string, string>
                                {
                                    ["RegistryPath"] = $"{rootName}\\{path}",
                                    ["ValueName"] = valueName,
                                    ["Value"] = valueStr
                                }
                            });
                        }

                        if (valueStrLower.Contains(@"\temp\") && !valueStrLower.Contains(@"\appdata\local\temp\"))
                        {
                            results.Add(new DetectionResult
                            {
                                Type = DetectionType.Registry,
                                Level = ThreatLevel.Medium,
                                Description = $"Autostart entry pointing to temp directory",
                                Details = $"Key: {rootName}\\{path}\\{valueName}, Value: {valueStr}",
                                Metadata = new Dictionary<string, string>
                                {
                                    ["RegistryPath"] = $"{rootName}\\{path}",
                                    ["ValueName"] = valueName,
                                    ["Value"] = valueStr
                                }
                            });
                        }
                    }
                    catch
                    {
                    }
                }
            }
            catch
            {
            }

            return results;
        }

        private List<DetectionResult> ScanForSuspiciousKeys(RegistryKey root, string path)
        {
            List<DetectionResult> results = [];

            try
            {
                using RegistryKey? key = root.OpenSubKey(path);
                if (key == null)
                    return results;

                string[] subKeyNames = key.GetSubKeyNames();

                foreach (string subKeyName in subKeyNames)
                {
                    if (_whitelistDatabase.IsTrustedService(subKeyName))
                        continue;

                    if (_signatureDatabase.IsKnownThreat(subKeyName.ToLowerInvariant()) ||
                        _signatureDatabase.IsSuspiciousPattern(subKeyName.ToLowerInvariant()))
                    {
                        results.Add(new DetectionResult
                        {
                            Type = DetectionType.Registry,
                            Level = ThreatLevel.Medium,
                            Description = $"Suspicious registry key detected",
                            Details = $"Key: HKLM\\{path}\\{subKeyName}",
                            Metadata = new Dictionary<string, string>
                            {
                                ["RegistryPath"] = $"HKLM\\{path}\\{subKeyName}"
                            }
                        });
                    }
                }
            }
            catch
            {
            }

            return results;
        }
    }
}