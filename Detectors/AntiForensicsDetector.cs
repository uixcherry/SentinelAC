using System.Diagnostics;
using SentinelAC.Core.Interfaces;
using SentinelAC.Core.Models;
using System.Runtime.Versioning;

namespace SentinelAC.Detectors
{
    [SupportedOSPlatform("windows")]
    public sealed class AntiForensicsDetector : IDetector
    {
        public DetectionType Type => DetectionType.Process;
        public bool RequiresAdminRights => false;

        private readonly string[] _antiForensicsTools =
        [
            "ccleaner", "privazer", "bleachbit", "eraser", "dban",
            "bcwipe", "file shredder", "secure delete", "evidence eliminator",
            "privacy eraser", "wipe", "sdelete", "cipher"
        ];

        private readonly string[] _suspiciousCleaningArgs =
        [
            "/cleaner", "/wipe", "/shred", "/secure", "/erase",
            "-w", "-p", "--wipe", "--clean", "--erase"
        ];

        public async Task<List<DetectionResult>> ScanAsync()
        {
            return await Task.Run(() =>
            {
                List<DetectionResult> results = [];

                CheckAntiForensicsProcesses(results);
                CheckPrefetchCleaning(results);
                CheckTempFolderAnomalies(results);

                return results;
            });
        }

        private void CheckAntiForensicsProcesses(List<DetectionResult> results)
        {
            Process[] processes = Process.GetProcesses();

            foreach (Process process in processes)
            {
                try
                {
                    string processName = process.ProcessName.ToLowerInvariant();
                    string commandLine = GetProcessCommandLine(process);

                    if (_antiForensicsTools.Any(tool => processName.Contains(tool)))
                    {
                        results.Add(new DetectionResult
                        {
                            Type = DetectionType.Process,
                            Level = ThreatLevel.Critical,
                            Description = $"Anti-forensics tool detected: {process.ProcessName}",
                            Details = $"Process ID: {process.Id}, Command: {commandLine}",
                            ConfidenceScore = 0.95,
                            Metadata = new Dictionary<string, string>
                            {
                                ["ProcessName"] = process.ProcessName,
                                ["ProcessId"] = process.Id.ToString(),
                                ["CommandLine"] = commandLine,
                                ["ToolType"] = "Privacy/Cleaning Tool"
                            }
                        });
                    }

                    if (_suspiciousCleaningArgs.Any(arg => commandLine.ToLowerInvariant().Contains(arg)))
                    {
                        results.Add(new DetectionResult
                        {
                            Type = DetectionType.Process,
                            Level = ThreatLevel.High,
                            Description = $"Suspicious cleaning arguments: {process.ProcessName}",
                            Details = $"Command line: {commandLine}",
                            ConfidenceScore = 0.80,
                            Metadata = new Dictionary<string, string>
                            {
                                ["ProcessName"] = process.ProcessName,
                                ["ProcessId"] = process.Id.ToString(),
                                ["CommandLine"] = commandLine
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

        private void CheckPrefetchCleaning(List<DetectionResult> results)
        {
            try
            {
                string prefetchPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

                if (Directory.Exists(prefetchPath))
                {
                    string[] prefetchFiles = Directory.GetFiles(prefetchPath, "*.pf");

                    if (prefetchFiles.Length < 5)
                    {
                        results.Add(new DetectionResult
                        {
                            Type = DetectionType.SystemManipulation,
                            Level = ThreatLevel.High,
                            Description = "Prefetch folder suspiciously empty",
                            Details = $"Only {prefetchFiles.Length} prefetch files - likely cleaned",
                            ConfidenceScore = 0.85,
                            Metadata = new Dictionary<string, string>
                            {
                                ["PrefetchPath"] = prefetchPath,
                                ["FileCount"] = prefetchFiles.Length.ToString(),
                                ["Expected"] = "Dozens to hundreds on normal system"
                            }
                        });
                    }
                }
            }
            catch
            {
            }
        }

        private void CheckTempFolderAnomalies(List<DetectionResult> results)
        {
            try
            {
                string tempPath = Path.GetTempPath();
                DirectoryInfo tempDir = new DirectoryInfo(tempPath);

                FileInfo[] files = tempDir.GetFiles();
                DirectoryInfo[] directories = tempDir.GetDirectories();

                int totalItems = files.Length + directories.Length;

                if (totalItems < 3)
                {
                    results.Add(new DetectionResult
                    {
                        Type = DetectionType.SystemManipulation,
                        Level = ThreatLevel.Medium,
                        Description = "Temp folder unusually clean",
                        Details = $"Only {totalItems} items in temp - possible recent cleaning",
                        ConfidenceScore = 0.70,
                        Metadata = new Dictionary<string, string>
                        {
                            ["TempPath"] = tempPath,
                            ["FileCount"] = files.Length.ToString(),
                            ["DirectoryCount"] = directories.Length.ToString(),
                            ["TotalItems"] = totalItems.ToString()
                        }
                    });
                }
            }
            catch
            {
            }
        }

        private string GetProcessCommandLine(Process process)
        {
            try
            {
                return process.StartInfo.Arguments;
            }
            catch
            {
                return string.Empty;
            }
        }
    }
}
