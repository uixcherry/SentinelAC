using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using SentinelAC.Core.Interfaces;
using SentinelAC.Core.Models;

namespace SentinelAC.Detectors
{
    [SupportedOSPlatform("windows")]
    public sealed class InputManipulationDetector : IDetector
    {
        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

        public DetectionType Type => DetectionType.InputManipulation;
        public bool RequiresAdminRights => false;

        public async Task<List<DetectionResult>> ScanAsync()
        {
            return await Task.Run(() =>
            {
                List<DetectionResult> results = [];

                CheckForAutoClickerSoftware(results);
                CheckForMacroSoftware(results);
                CheckForInputInjectors(results);

                return results;
            });
        }

        private static void CheckForAutoClickerSoftware(List<DetectionResult> results)
        {
            string[] autoClickerProcesses =
            [
                "autoclicker", "op autoclicker", "gsautoclicker", "fastclicker",
                "mouserecorder", "tinytask", "pulover", "autohotkey", "ahk"
            ];

            Process[] processes = Process.GetProcesses();
            foreach (Process process in processes)
            {
                try
                {
                    string processName = process.ProcessName.ToLowerInvariant();

                    if (autoClickerProcesses.Any(ac => processName.Contains(ac)))
                    {
                        results.Add(new DetectionResult
                        {
                            Type = DetectionType.InputManipulation,
                            Level = ThreatLevel.High,
                            Description = $"Auto-clicker software detected: {process.ProcessName}",
                            Details = $"Process ID: {process.Id}, Path: {GetProcessPath(process)}",
                            Metadata = new Dictionary<string, string>
                            {
                                ["ProcessName"] = process.ProcessName,
                                ["ProcessId"] = process.Id.ToString(),
                                ["Path"] = GetProcessPath(process)
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

        private static void CheckForMacroSoftware(List<DetectionResult> results)
        {
            string[] macroSoftware =
            [
                "razer synapse", "logitech gaming", "ghub", "corsair icue",
                "steelseries engine", "xmouse", "jitbit", "macro recorder"
            ];

            Process[] processes = Process.GetProcesses();
            foreach (Process process in processes)
            {
                try
                {
                    string processName = process.ProcessName.ToLowerInvariant();

                    if (macroSoftware.Any(ms => processName.Contains(ms)))
                    {
                        results.Add(new DetectionResult
                        {
                            Type = DetectionType.InputManipulation,
                            Level = ThreatLevel.Low,
                            Description = $"Macro-capable software detected: {process.ProcessName}",
                            Details = $"Process ID: {process.Id} (Note: Gaming peripherals software can be legitimate)",
                            Metadata = new Dictionary<string, string>
                            {
                                ["ProcessName"] = process.ProcessName,
                                ["ProcessId"] = process.Id.ToString(),
                                ["Type"] = "PeripheralSoftware"
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

        private static void CheckForInputInjectors(List<DetectionResult> results)
        {
            string[] suspiciousLibraries =
            [
                "interception", "inputsimulator", "sendinput", "windowsinput"
            ];

            Process[] processes = Process.GetProcesses();
            foreach (Process process in processes)
            {
                try
                {
                    foreach (ProcessModule module in process.Modules)
                    {
                        string moduleName = module.ModuleName.ToLowerInvariant();

                        if (suspiciousLibraries.Any(lib => moduleName.Contains(lib)))
                        {
                            results.Add(new DetectionResult
                            {
                                Type = DetectionType.InputManipulation,
                                Level = ThreatLevel.Medium,
                                Description = $"Input injection library detected: {module.ModuleName}",
                                Details = $"Process: {process.ProcessName}, Module: {module.FileName}",
                                Metadata = new Dictionary<string, string>
                                {
                                    ["ProcessName"] = process.ProcessName,
                                    ["ModuleName"] = module.ModuleName,
                                    ["ModulePath"] = module.FileName
                                }
                            });
                        }
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

        private static string GetProcessPath(Process process)
        {
            try
            {
                return process.MainModule?.FileName ?? "Unknown";
            }
            catch
            {
                return "Unknown";
            }
        }
    }
}