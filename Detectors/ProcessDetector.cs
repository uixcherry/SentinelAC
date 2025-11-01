using System.Diagnostics;
using System.Runtime.InteropServices;
using SentinelAC.Core.Data;
using SentinelAC.Core.Interfaces;
using SentinelAC.Core.Models;

namespace SentinelAC.Detectors
{
    public sealed class ProcessDetector : IDetector
    {
        private readonly ISignatureDatabase _signatureDatabase;
        private readonly WhitelistDatabase _whitelistDatabase;

        [DllImport("kernel32.dll")]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

        public DetectionType Type => DetectionType.Process;
        public bool RequiresAdminRights => false;

        public ProcessDetector(ISignatureDatabase signatureDatabase, WhitelistDatabase whitelistDatabase)
        {
            _signatureDatabase = signatureDatabase;
            _whitelistDatabase = whitelistDatabase;
        }

        public async Task<List<DetectionResult>> ScanAsync()
        {
            return await Task.Run(() =>
            {
                List<DetectionResult> results = [];
                Process[] processes = Process.GetProcesses();

                foreach (Process process in processes)
                {
                    try
                    {
                        DetectionResult? result = AnalyzeProcess(process);
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
                        process.Dispose();
                    }
                }

                DetectionResult? debuggerResult = CheckForDebuggers();
                if (debuggerResult != null)
                {
                    results.Add(debuggerResult);
                }

                return results;
            });
        }

        private DetectionResult? AnalyzeProcess(Process process)
        {
            string processName = process.ProcessName.ToLowerInvariant();
            string fullPath = string.Empty;

            try
            {
                fullPath = process.MainModule?.FileName ?? string.Empty;
            }
            catch
            {
            }

            if (processName.Contains("sentinelac"))
                return null;

            if (_whitelistDatabase.IsTrustedProcess(processName))
                return null;

            if (_signatureDatabase.IsKnownThreat(processName))
            {
                return new DetectionResult
                {
                    Type = DetectionType.Process,
                    Level = ThreatLevel.Critical,
                    Description = $"Known cheat process detected: {process.ProcessName}",
                    Details = $"Process ID: {process.Id}, Path: {fullPath}",
                    Metadata = new Dictionary<string, string>
                    {
                        ["ProcessName"] = process.ProcessName,
                        ["ProcessId"] = process.Id.ToString(),
                        ["Path"] = fullPath,
                        ["StartTime"] = process.StartTime.ToString("yyyy-MM-dd HH:mm:ss")
                    }
                };
            }

            if (_signatureDatabase.IsSuspiciousPattern(processName))
            {
                return new DetectionResult
                {
                    Type = DetectionType.Process,
                    Level = ThreatLevel.High,
                    Description = $"Suspicious process detected: {process.ProcessName}",
                    Details = $"Process ID: {process.Id}, Path: {fullPath}",
                    Metadata = new Dictionary<string, string>
                    {
                        ["ProcessName"] = process.ProcessName,
                        ["ProcessId"] = process.Id.ToString(),
                        ["Path"] = fullPath,
                        ["StartTime"] = process.StartTime.ToString("yyyy-MM-dd HH:mm:ss")
                    }
                };
            }

            if (IsDebuggerProcess(processName) && !_whitelistDatabase.IsTrustedProcess(processName))
            {
                return new DetectionResult
                {
                    Type = DetectionType.Process,
                    Level = ThreatLevel.High,
                    Description = $"Debugger process detected: {process.ProcessName}",
                    Details = $"Process ID: {process.Id}, Path: {fullPath}",
                    Metadata = new Dictionary<string, string>
                    {
                        ["ProcessName"] = process.ProcessName,
                        ["ProcessId"] = process.Id.ToString(),
                        ["Path"] = fullPath
                    }
                };
            }

            return null;
        }

        private static bool IsDebuggerProcess(string processName)
        {
            string[] debuggers = ["x64dbg", "x32dbg", "ollydbg", "windbg", "ida", "ida64", "cheatengine"];
            return debuggers.Any(d => processName.Contains(d));
        }

        private static DetectionResult? CheckForDebuggers()
        {
            if (Debugger.IsAttached)
            {
                return new DetectionResult
                {
                    Type = DetectionType.Process,
                    Level = ThreatLevel.Low,
                    Description = "Development debugger attached",
                    Details = "Managed debugger detected (Visual Studio or similar IDE)",
                    Metadata = new Dictionary<string, string>
                    {
                        ["DebuggerType"] = "Managed"
                    }
                };
            }

            return null;
        }
    }
}