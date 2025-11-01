using System.Diagnostics;
using System.Runtime.Versioning;
using SentinelAC.Core.Interfaces;
using SentinelAC.Core.Models;

namespace SentinelAC.Detectors
{
    [SupportedOSPlatform("windows")]
    public sealed class EventLogTamperingDetector : IDetector
    {
        public DetectionType Type => DetectionType.SystemManipulation;
        public bool RequiresAdminRights => false;

        public async Task<List<DetectionResult>> ScanAsync()
        {
            return await Task.Run(() =>
            {
                List<DetectionResult> results = [];

                CheckEventLogSize(results);
                CheckRecentEventLogClearing(results);
                CheckEventLogService(results);

                return results;
            });
        }

        private void CheckEventLogSize(List<DetectionResult> results)
        {
            try
            {
                string[] criticalLogs = ["Application", "System", "Security"];

                foreach (string logName in criticalLogs)
                {
                    try
                    {
                        EventLog eventLog = new EventLog(logName);

                        if (eventLog.Entries.Count < 10)
                        {
                            results.Add(new DetectionResult
                            {
                                Type = DetectionType.SystemManipulation,
                                Level = ThreatLevel.Critical,
                                Description = $"{logName} event log suspiciously small",
                                Details = $"Only {eventLog.Entries.Count} entries - likely cleared recently",
                                ConfidenceScore = 0.95,
                                Metadata = new Dictionary<string, string>
                                {
                                    ["LogName"] = logName,
                                    ["EntryCount"] = eventLog.Entries.Count.ToString(),
                                    ["Expected"] = "Hundreds or thousands on normal system"
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
        }

        private void CheckRecentEventLogClearing(List<DetectionResult> results)
        {
            try
            {
                EventLog systemLog = new EventLog("System");
                DateTime cutoffTime = DateTime.Now.AddHours(-24);

                List<EventLogEntry> clearEvents = [];

                foreach (EventLogEntry entry in systemLog.Entries)
                {
                    if (entry.TimeGenerated > cutoffTime &&
                        entry.Source == "Microsoft-Windows-Eventlog" &&
                        entry.InstanceId == 104)
                    {
                        clearEvents.Add(entry);
                    }
                }

                if (clearEvents.Count > 0)
                {
                    string clearedLogs = string.Join(", ", clearEvents.Select(e =>
                        e.TimeGenerated.ToString("yyyy-MM-dd HH:mm:ss")));

                    results.Add(new DetectionResult
                    {
                        Type = DetectionType.SystemManipulation,
                        Level = ThreatLevel.Critical,
                        Description = "Event logs cleared in last 24 hours",
                        Details = $"Detected {clearEvents.Count} log clearing event(s): {clearedLogs}",
                        ConfidenceScore = 0.98,
                        Metadata = new Dictionary<string, string>
                        {
                            ["ClearEventCount"] = clearEvents.Count.ToString(),
                            ["EventID"] = "104",
                            ["TimeFrame"] = "Last 24 hours",
                            ["Severity"] = "Critical - Active anti-forensics"
                        }
                    });
                }
            }
            catch
            {
            }
        }

        private void CheckEventLogService(List<DetectionResult> results)
        {
            try
            {
                Process[] processes = Process.GetProcesses();
                bool eventLogServiceRunning = processes.Any(p =>
                {
                    try
                    {
                        return p.ProcessName.ToLowerInvariant() == "eventlog" ||
                               p.ProcessName.ToLowerInvariant() == "wevtsvc";
                    }
                    catch
                    {
                        return false;
                    }
                });

                foreach (Process p in processes)
                {
                    p.Dispose();
                }

                if (!eventLogServiceRunning)
                {
                    results.Add(new DetectionResult
                    {
                        Type = DetectionType.SystemManipulation,
                        Level = ThreatLevel.Critical,
                        Description = "Windows Event Log service not running",
                        Details = "Service disabled or stopped - severe tampering detected",
                        ConfidenceScore = 1.0,
                        Metadata = new Dictionary<string, string>
                        {
                            ["ServiceName"] = "EventLog",
                            ["Status"] = "Not Running",
                            ["Severity"] = "Critical"
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
