using Microsoft.Win32;
using SentinelAC.Core.Interfaces;
using SentinelAC.Core.Models;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace SentinelAC.Detectors
{
    [SupportedOSPlatform("windows")]
    public sealed class SandboxDetector : IDetector
    {
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        public DetectionType Type => DetectionType.Sandbox;
        public bool RequiresAdminRights => false;

        private readonly string[] _sandboxProcesses =
        [
            "vmsrvc", "vmusrvc", "vboxtray", "vmtoolsd",
            "sandboxie", "sbiesvc", "wireshark", "fiddler",
            "procmon", "procmon64", "procexp", "procexp64"
        ];

        private readonly string[] _sandboxDrivers =
        [
            "sbiedll", "vboxmouse", "vboxguest", "vboxsf",
            "vboxvideo", "vmhgfs", "vmmemctl"
        ];

        private readonly string[] _sandboxFiles =
        [
            @"C:\Sandbox", @"C:\CWSandbox", @"C:\Analysis",
            @"C:\insidetm", @"C:\popupkiller"
        ];

        public async Task<List<DetectionResult>> ScanAsync()
        {
            return await Task.Run(() =>
            {
                List<DetectionResult> results = [];

                CheckSandboxProcesses(results);
                CheckSandboxDrivers(results);
                CheckSandboxFiles(results);
                CheckSandboxRegistry(results);
                CheckVirtualEnvironment(results);
                CheckCuckooSandbox(results);
                CheckTimingAnomalies(results);

                return results;
            });
        }

        private void CheckSandboxProcesses(List<DetectionResult> results)
        {
            Process[] processes = Process.GetProcesses();
            foreach (Process process in processes)
            {
                try
                {
                    string processName = process.ProcessName.ToLowerInvariant();
                    if (_sandboxProcesses.Any(sb => processName.Contains(sb)))
                    {
                        results.Add(new DetectionResult
                        {
                            Type = DetectionType.Sandbox,
                            Level = ThreatLevel.High,
                            Description = $"Sandbox process detected: {process.ProcessName}",
                            Details = $"Process ID: {process.Id}",
                            Metadata = new Dictionary<string, string>
                            {
                                ["ProcessName"] = process.ProcessName,
                                ["ProcessId"] = process.Id.ToString(),
                                ["DetectionType"] = "Process"
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

        private void CheckSandboxDrivers(List<DetectionResult> results)
        {
            foreach (string driver in _sandboxDrivers)
            {
                IntPtr handle = GetModuleHandle(driver + ".sys");
                if (handle != IntPtr.Zero)
                {
                    results.Add(new DetectionResult
                    {
                        Type = DetectionType.Sandbox,
                        Level = ThreatLevel.High,
                        Description = $"Sandbox driver detected: {driver}",
                        Details = $"Driver module loaded in memory",
                        Metadata = new Dictionary<string, string>
                        {
                            ["DriverName"] = driver,
                            ["DetectionType"] = "Driver"
                        }
                    });
                }
            }
        }

        private void CheckSandboxFiles(List<DetectionResult> results)
        {
            foreach (string path in _sandboxFiles)
            {
                if (Directory.Exists(path))
                {
                    results.Add(new DetectionResult
                    {
                        Type = DetectionType.Sandbox,
                        Level = ThreatLevel.High,
                        Description = $"Sandbox directory detected: {path}",
                        Details = "Common sandbox installation directory found",
                        Metadata = new Dictionary<string, string>
                        {
                            ["Path"] = path,
                            ["DetectionType"] = "FileSystem"
                        }
                    });
                }
            }
        }

        private void CheckSandboxRegistry(List<DetectionResult> results)
        {
            try
            {
                string[] sandboxKeys =
                [
                    @"SOFTWARE\Sandboxie",
                    @"SOFTWARE\VMware, Inc.\VMware Tools",
                    @"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0"
                ];

                foreach (string keyPath in sandboxKeys)
                {
                    using RegistryKey? key = Registry.LocalMachine.OpenSubKey(keyPath);
                    if (key != null)
                    {
                        results.Add(new DetectionResult
                        {
                            Type = DetectionType.Sandbox,
                            Level = ThreatLevel.High,
                            Description = "Sandbox registry key detected",
                            Details = $"Key: HKLM\\{keyPath}",
                            Metadata = new Dictionary<string, string>
                            {
                                ["RegistryKey"] = keyPath,
                                ["DetectionType"] = "Registry"
                            }
                        });
                    }
                }

                using RegistryKey? scsiKey = Registry.LocalMachine.OpenSubKey(
                    @"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0");
                if (scsiKey != null)
                {
                    string? identifier = scsiKey.GetValue("Identifier")?.ToString()?.ToLowerInvariant();
                    if (!string.IsNullOrEmpty(identifier) &&
                        (identifier.Contains("vbox") || identifier.Contains("vmware") || identifier.Contains("qemu")))
                    {
                        results.Add(new DetectionResult
                        {
                            Type = DetectionType.Sandbox,
                            Level = ThreatLevel.High,
                            Description = "Virtual disk identifier detected",
                            Details = $"Identifier: {identifier}",
                            Metadata = new Dictionary<string, string>
                            {
                                ["Identifier"] = identifier,
                                ["DetectionType"] = "DiskIdentifier"
                            }
                        });
                    }
                }
            }
            catch
            {
            }
        }

        private void CheckVirtualEnvironment(List<DetectionResult> results)
        {
            try
            {
                using ManagementObjectSearcher searcher = new("SELECT * FROM Win32_ComputerSystem");
                foreach (ManagementObject obj in searcher.Get())
                {
                    string manufacturer = obj["Manufacturer"]?.ToString()?.ToLowerInvariant() ?? string.Empty;
                    string model = obj["Model"]?.ToString()?.ToLowerInvariant() ?? string.Empty;

                    if (manufacturer.Contains("vmware") || manufacturer.Contains("innotek") ||
                        model.Contains("virtualbox") || model.Contains("vmware"))
                    {
                        results.Add(new DetectionResult
                        {
                            Type = DetectionType.Sandbox,
                            Level = ThreatLevel.High,
                            Description = "Virtual environment detected via WMI",
                            Details = $"Manufacturer: {manufacturer}, Model: {model}",
                            Metadata = new Dictionary<string, string>
                            {
                                ["Manufacturer"] = manufacturer,
                                ["Model"] = model,
                                ["DetectionType"] = "WMI"
                            }
                        });
                    }
                }
            }
            catch
            {
            }
        }

        private void CheckCuckooSandbox(List<DetectionResult> results)
        {
            try
            {
                string[] cuckooArtifacts =
                [
                    @"C:\cuckoo", @"C:\analyzer.py", @"C:\agent.py"
                ];

                foreach (string artifact in cuckooArtifacts)
                {
                    if (File.Exists(artifact) || Directory.Exists(artifact))
                    {
                        results.Add(new DetectionResult
                        {
                            Type = DetectionType.Sandbox,
                            Level = ThreatLevel.Critical,
                            Description = "Cuckoo Sandbox artifact detected",
                            Details = $"Artifact: {artifact}",
                            Metadata = new Dictionary<string, string>
                            {
                                ["Artifact"] = artifact,
                                ["DetectionType"] = "CuckooSandbox"
                            }
                        });
                    }
                }

                if (Environment.UserName.ToLowerInvariant() == "currentuser" ||
                    Environment.UserName.ToLowerInvariant() == "sandbox")
                {
                    results.Add(new DetectionResult
                    {
                        Type = DetectionType.Sandbox,
                        Level = ThreatLevel.High,
                        Description = "Suspicious username detected",
                        Details = $"Username: {Environment.UserName}",
                        Metadata = new Dictionary<string, string>
                        {
                            ["Username"] = Environment.UserName,
                            ["DetectionType"] = "Username"
                        }
                    });
                }
            }
            catch
            {
            }
        }

        private void CheckTimingAnomalies(List<DetectionResult> results)
        {
            try
            {
                Stopwatch sw = Stopwatch.StartNew();
                Thread.Sleep(500);
                sw.Stop();

                if (sw.ElapsedMilliseconds < 450 || sw.ElapsedMilliseconds > 550)
                {
                    results.Add(new DetectionResult
                    {
                        Type = DetectionType.Sandbox,
                        Level = ThreatLevel.Medium,
                        Description = "Timing anomaly detected",
                        Details = $"Expected ~500ms, measured {sw.ElapsedMilliseconds}ms (possible time manipulation)",
                        Metadata = new Dictionary<string, string>
                        {
                            ["ExpectedMs"] = "500",
                            ["ActualMs"] = sw.ElapsedMilliseconds.ToString(),
                            ["DetectionType"] = "Timing"
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