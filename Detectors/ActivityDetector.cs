using SentinelAC.Core.Interfaces;
using SentinelAC.Core.Models;
using System.Diagnostics;

namespace SentinelAC.Detectors
{
    public sealed class ActivityDetector : IDetector
    {
        private readonly Dictionary<string, DateTime> _processActivityLog;
        private readonly string _logFilePath;

        public DetectionType Type => DetectionType.Activity;
        public bool RequiresAdminRights => false;

        public ActivityDetector(string logFilePath = "activity_log.txt")
        {
            _logFilePath = logFilePath;
            _processActivityLog = [];
            LoadActivityLog();
        }

        public async Task<List<DetectionResult>> ScanAsync()
        {
            return await Task.Run(() =>
            {
                List<DetectionResult> results = [];
                Process[] processes = Process.GetProcesses();
                DateTime now = DateTime.UtcNow;

                foreach (Process process in processes)
                {
                    try
                    {
                        string processKey = $"{process.ProcessName}_{process.Id}";
                        DateTime startTime = process.StartTime;

                        if (!_processActivityLog.ContainsKey(processKey))
                        {
                            _processActivityLog[processKey] = startTime;

                            if ((now - startTime).TotalMinutes < 5)
                            {
                                string processName = process.ProcessName.ToLowerInvariant();

                                if (IsSuspiciousRecentActivity(processName))
                                {
                                    results.Add(new DetectionResult
                                    {
                                        Type = DetectionType.Activity,
                                        Level = ThreatLevel.Medium,
                                        Description = $"Suspicious process started recently: {process.ProcessName}",
                                        Details = $"Process ID: {process.Id}, Started: {startTime:yyyy-MM-dd HH:mm:ss}",
                                        Metadata = new Dictionary<string, string>
                                        {
                                            ["ProcessName"] = process.ProcessName,
                                            ["ProcessId"] = process.Id.ToString(),
                                            ["StartTime"] = startTime.ToString("yyyy-MM-dd HH:mm:ss"),
                                            ["TimeSinceStart"] = $"{(now - startTime).TotalMinutes:F2} minutes"
                                        }
                                    });
                                }
                            }
                        }

                        TimeSpan uptime = now - startTime;
                        if (uptime.TotalHours > 24 && IsSuspiciousLongRunning(process.ProcessName.ToLowerInvariant()))
                        {
                            results.Add(new DetectionResult
                            {
                                Type = DetectionType.Activity,
                                Level = ThreatLevel.Low,
                                Description = $"Suspicious process running for extended period: {process.ProcessName}",
                                Details = $"Process ID: {process.Id}, Uptime: {uptime.TotalHours:F2} hours",
                                Metadata = new Dictionary<string, string>
                                {
                                    ["ProcessName"] = process.ProcessName,
                                    ["ProcessId"] = process.Id.ToString(),
                                    ["StartTime"] = startTime.ToString("yyyy-MM-dd HH:mm:ss"),
                                    ["UptimeHours"] = uptime.TotalHours.ToString("F2")
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

                SaveActivityLog();
                return results;
            });
        }

        private bool IsSuspiciousRecentActivity(string processName)
        {
            string[] suspiciousNames =
            [
                "cheat", "hack", "trainer", "inject", "bypass",
                "crack", "keygen", "patch", "loader", "hook"
            ];
            return suspiciousNames.Any(s => processName.Contains(s));
        }

        private bool IsSuspiciousLongRunning(string processName)
        {
            string[] longRunningThreats =
            [
                "miner", "cryptonight", "xmrig", "botnet", "rat"
            ];
            return longRunningThreats.Any(s => processName.Contains(s));
        }

        private void LoadActivityLog()
        {
            try
            {
                if (File.Exists(_logFilePath))
                {
                    string[] lines = File.ReadAllLines(_logFilePath);
                    foreach (string line in lines)
                    {
                        string[] parts = line.Split('|');
                        if (parts.Length == 2)
                        {
                            if (DateTime.TryParse(parts[1], out DateTime timestamp))
                            {
                                _processActivityLog[parts[0]] = timestamp;
                            }
                        }
                    }
                }
            }
            catch
            {
            }
        }

        private void SaveActivityLog()
        {
            try
            {
                List<string> lines = [];
                DateTime cutoff = DateTime.UtcNow.AddDays(-7);

                foreach (KeyValuePair<string, DateTime> entry in _processActivityLog)
                {
                    if (entry.Value > cutoff)
                    {
                        lines.Add($"{entry.Key}|{entry.Value:yyyy-MM-dd HH:mm:ss}");
                    }
                }

                File.WriteAllLines(_logFilePath, lines);
            }
            catch
            {
            }
        }
    }
}