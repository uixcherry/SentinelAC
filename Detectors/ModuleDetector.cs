using System.Diagnostics;
using SentinelAC.Core.Data;
using SentinelAC.Core.Interfaces;
using SentinelAC.Core.Models;

namespace SentinelAC.Detectors
{
    public sealed class ModuleDetector : IDetector
    {
        private readonly ISignatureDatabase _signatureDatabase;
        private readonly WhitelistDatabase _whitelistDatabase;

        public DetectionType Type => DetectionType.Module;
        public bool RequiresAdminRights => true;

        public ModuleDetector(ISignatureDatabase signatureDatabase, WhitelistDatabase whitelistDatabase)
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
                        string processName = process.ProcessName.ToLowerInvariant();

                        if (processName.Contains("sentinelac"))
                            continue;

                        if (_whitelistDatabase.IsTrustedProcess(process.ProcessName))
                            continue;

                        List<DetectionResult> moduleResults = AnalyzeProcessModules(process);
                        results.AddRange(moduleResults);
                    }
                    catch
                    {
                    }
                    finally
                    {
                        process.Dispose();
                    }
                }

                return results;
            });
        }

        private List<DetectionResult> AnalyzeProcessModules(Process process)
        {
            List<DetectionResult> results = [];

            try
            {
                ProcessModuleCollection modules = process.Modules;

                foreach (ProcessModule module in modules)
                {
                    try
                    {
                        DetectionResult? result = AnalyzeModule(module, process);
                        if (result != null)
                        {
                            results.Add(result);
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

        private DetectionResult? AnalyzeModule(ProcessModule module, Process process)
        {
            string moduleName = Path.GetFileNameWithoutExtension(module.ModuleName).ToLowerInvariant();
            string fullPath = module.FileName.ToLowerInvariant();

            if (_whitelistDatabase.IsTrustedModule(moduleName))
                return null;

            if (_whitelistDatabase.IsTrustedPath(fullPath))
                return null;

            if (_signatureDatabase.IsKnownThreat(moduleName))
            {
                return new DetectionResult
                {
                    Type = DetectionType.Module,
                    Level = ThreatLevel.Critical,
                    Description = $"Known cheat module loaded: {module.ModuleName}",
                    Details = $"Process: {process.ProcessName} (PID: {process.Id}), Module Path: {module.FileName}",
                    Metadata = new Dictionary<string, string>
                    {
                        ["ModuleName"] = module.ModuleName,
                        ["ProcessName"] = process.ProcessName,
                        ["ProcessId"] = process.Id.ToString(),
                        ["ModulePath"] = module.FileName,
                        ["ModuleSize"] = module.ModuleMemorySize.ToString()
                    }
                };
            }

            if (_signatureDatabase.IsSuspiciousPattern(moduleName))
            {
                return new DetectionResult
                {
                    Type = DetectionType.Module,
                    Level = ThreatLevel.High,
                    Description = $"Suspicious module loaded: {module.ModuleName}",
                    Details = $"Process: {process.ProcessName} (PID: {process.Id}), Module Path: {module.FileName}",
                    Metadata = new Dictionary<string, string>
                    {
                        ["ModuleName"] = module.ModuleName,
                        ["ProcessName"] = process.ProcessName,
                        ["ProcessId"] = process.Id.ToString(),
                        ["ModulePath"] = module.FileName,
                        ["ModuleSize"] = module.ModuleMemorySize.ToString()
                    }
                };
            }

            if (IsInjectionDll(module, process))
            {
                return new DetectionResult
                {
                    Type = DetectionType.Module,
                    Level = ThreatLevel.High,
                    Description = $"Potential DLL injection detected: {module.ModuleName}",
                    Details = $"Process: {process.ProcessName} (PID: {process.Id}), Suspicious module location",
                    Metadata = new Dictionary<string, string>
                    {
                        ["ModuleName"] = module.ModuleName,
                        ["ProcessName"] = process.ProcessName,
                        ["ProcessId"] = process.Id.ToString(),
                        ["ModulePath"] = module.FileName
                    }
                };
            }

            return null;
        }

        private bool IsInjectionDll(ProcessModule module, Process process)
        {
            string modulePath = module.FileName.ToLowerInvariant();
            string processPath = string.Empty;

            try
            {
                processPath = Path.GetDirectoryName(process.MainModule?.FileName)?.ToLowerInvariant() ?? string.Empty;
            }
            catch
            {
                return false;
            }

            if (string.IsNullOrEmpty(processPath))
                return false;

            string moduleDirectory = Path.GetDirectoryName(modulePath) ?? string.Empty;

            if (_whitelistDatabase.IsTrustedPath(moduleDirectory))
                return false;

            bool isProcessModule = moduleDirectory.StartsWith(processPath);

            if (!isProcessModule)
            {
                string[] suspiciousLocations = [@"\temp\", @"\downloads\", @"\desktop\"];
                return suspiciousLocations.Any(loc => modulePath.Contains(loc));
            }

            return false;
        }
    }
}