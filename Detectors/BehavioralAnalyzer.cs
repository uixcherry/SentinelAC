using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using SentinelAC.Core.Interfaces;
using SentinelAC.Core.Models;

namespace SentinelAC.Detectors
{
    [SupportedOSPlatform("windows")]
    public sealed class BehavioralAnalyzer : IDetector
    {
        [DllImport("user32.dll")]
        private static extern short GetAsyncKeyState(int vKey);

        [DllImport("user32.dll")]
        private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

        [StructLayout(LayoutKind.Sequential)]
        private struct LASTINPUTINFO
        {
            public uint cbSize;
            public uint dwTime;
        }

        public DetectionType Type => DetectionType.Activity;
        public bool RequiresAdminRights => false;

        private readonly Dictionary<int, BehaviorProfile> _behaviorProfiles;
        private readonly List<InputEvent> _inputHistory;
        private const int MAX_INPUT_HISTORY = 1000;
        private const double ROBOT_PRECISION_THRESHOLD = 0.98;
        private const double CORRELATION_THRESHOLD = 0.85;

        public BehavioralAnalyzer()
        {
            _behaviorProfiles = new Dictionary<int, BehaviorProfile>();
            _inputHistory = new List<InputEvent>();
        }

        public async Task<List<DetectionResult>> ScanAsync()
        {
            return await Task.Run(() =>
            {
                List<DetectionResult> results = [];

                AnalyzeProcessBehavior(results);
                DetectRoboticPatterns(results);
                AnalyzeInputFrequency(results);
                DetectCorrelatedBehavior(results);

                return results;
            });
        }

        private void AnalyzeProcessBehavior(List<DetectionResult> results)
        {
            Process[] processes = Process.GetProcesses();

            foreach (Process process in processes)
            {
                try
                {
                    int processId = process.Id;

                    if (!_behaviorProfiles.ContainsKey(processId))
                    {
                        _behaviorProfiles[processId] = new BehaviorProfile
                        {
                            ProcessId = processId,
                            ProcessName = process.ProcessName,
                            StartTime = process.StartTime
                        };
                    }

                    BehaviorProfile profile = _behaviorProfiles[processId];
                    profile.Observations.Add(new BehaviorObservation
                    {
                        Timestamp = DateTime.UtcNow,
                        CpuTime = process.TotalProcessorTime.TotalMilliseconds,
                        MemoryUsage = process.WorkingSet64,
                        ThreadCount = process.Threads.Count,
                        HandleCount = process.HandleCount
                    });

                    if (profile.Observations.Count > 100)
                    {
                        profile.Observations.RemoveAt(0);
                    }

                    if (profile.Observations.Count >= 20)
                    {
                        double cpuVariance = CalculateVariance(profile.Observations.Select(o => o.CpuTime).ToArray());
                        double memoryVariance = CalculateVariance(profile.Observations.Select(o => (double)o.MemoryUsage).ToArray());

                        if (cpuVariance < 0.01 && profile.Observations.Count > 30)
                        {
                            results.Add(new DetectionResult
                            {
                                Type = DetectionType.Activity,
                                Level = ThreatLevel.Medium,
                                Description = $"Suspiciously consistent CPU usage pattern: {process.ProcessName}",
                                Details = $"Process ID: {processId}, Variance: {cpuVariance:F6} (possible automation)",
                                Metadata = new Dictionary<string, string>
                                {
                                    ["ProcessName"] = process.ProcessName,
                                    ["ProcessId"] = processId.ToString(),
                                    ["CpuVariance"] = cpuVariance.ToString("F8"),
                                    ["ObservationCount"] = profile.Observations.Count.ToString(),
                                    ["AnalysisType"] = "CpuConsistency"
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

        private void DetectRoboticPatterns(List<DetectionResult> results)
        {
            RecordInputEvents();

            if (_inputHistory.Count < 50)
                return;

            List<double> intervals = [];
            for (int i = 1; i < _inputHistory.Count; i++)
            {
                TimeSpan interval = _inputHistory[i].Timestamp - _inputHistory[i - 1].Timestamp;
                intervals.Add(interval.TotalMilliseconds);
            }

            double meanInterval = intervals.Average();
            double stdDeviation = CalculateStandardDeviation(intervals.ToArray(), meanInterval);
            double coefficientOfVariation = stdDeviation / meanInterval;

            if (coefficientOfVariation < (1 - ROBOT_PRECISION_THRESHOLD))
            {
                results.Add(new DetectionResult
                {
                    Type = DetectionType.InputManipulation,
                    Level = ThreatLevel.High,
                    Description = "Robotic input pattern detected (extremely consistent timing)",
                    Details = $"CoV: {coefficientOfVariation:F4}, Mean: {meanInterval:F2}ms, StdDev: {stdDeviation:F2}ms",
                    Metadata = new Dictionary<string, string>
                    {
                        ["CoefficientOfVariation"] = coefficientOfVariation.ToString("F6"),
                        ["MeanInterval"] = meanInterval.ToString("F2"),
                        ["StandardDeviation"] = stdDeviation.ToString("F2"),
                        ["SampleSize"] = intervals.Count.ToString(),
                        ["AnalysisType"] = "RoboticTiming"
                    }
                });
            }

            List<double> sequentialDifferences = [];
            for (int i = 1; i < intervals.Count; i++)
            {
                sequentialDifferences.Add(Math.Abs(intervals[i] - intervals[i - 1]));
            }

            double meanSequentialDiff = sequentialDifferences.Average();

            if (meanSequentialDiff < 5.0 && intervals.Count > 30)
            {
                results.Add(new DetectionResult
                {
                    Type = DetectionType.InputManipulation,
                    Level = ThreatLevel.Critical,
                    Description = "Automated input detected (perfect sequential consistency)",
                    Details = $"Mean sequential difference: {meanSequentialDiff:F2}ms (human input typically varies more)",
                    Metadata = new Dictionary<string, string>
                    {
                        ["MeanSequentialDiff"] = meanSequentialDiff.ToString("F4"),
                        ["SampleSize"] = sequentialDifferences.Count.ToString(),
                        ["AnalysisType"] = "SequentialConsistency"
                    }
                });
            }
        }

        private void AnalyzeInputFrequency(List<DetectionResult> results)
        {
            if (_inputHistory.Count < 30)
                return;

            DateTime windowStart = DateTime.UtcNow.AddSeconds(-60);
            List<InputEvent> recentEvents = _inputHistory.Where(e => e.Timestamp > windowStart).ToList();

            if (recentEvents.Count > 0)
            {
                double eventsPerSecond = recentEvents.Count / 60.0;

                if (eventsPerSecond > 20)
                {
                    results.Add(new DetectionResult
                    {
                        Type = DetectionType.InputManipulation,
                        Level = ThreatLevel.High,
                        Description = "Abnormally high input frequency detected",
                        Details = $"Input rate: {eventsPerSecond:F2} events/second (typical human: 2-5 events/second)",
                        Metadata = new Dictionary<string, string>
                        {
                            ["EventsPerSecond"] = eventsPerSecond.ToString("F2"),
                            ["EventCount"] = recentEvents.Count.ToString(),
                            ["WindowSeconds"] = "60",
                            ["AnalysisType"] = "FrequencyAnalysis"
                        }
                    });
                }

                Dictionary<int, int> keyPressCounts = [];
                foreach (InputEvent evt in recentEvents)
                {
                    if (!keyPressCounts.ContainsKey(evt.KeyCode))
                        keyPressCounts[evt.KeyCode] = 0;
                    keyPressCounts[evt.KeyCode]++;
                }

                KeyValuePair<int, int> mostPressed = keyPressCounts.OrderByDescending(kvp => kvp.Value).FirstOrDefault();

                if (mostPressed.Value > recentEvents.Count * 0.8)
                {
                    results.Add(new DetectionResult
                    {
                        Type = DetectionType.InputManipulation,
                        Level = ThreatLevel.High,
                        Description = "Repetitive single-key input pattern detected",
                        Details = $"Key {mostPressed.Key} pressed {mostPressed.Value} times ({(double)mostPressed.Value / recentEvents.Count:P0} of all inputs)",
                        Metadata = new Dictionary<string, string>
                        {
                            ["DominantKeyCode"] = mostPressed.Key.ToString(),
                            ["PressCount"] = mostPressed.Value.ToString(),
                            ["TotalEvents"] = recentEvents.Count.ToString(),
                            ["Percentage"] = ((double)mostPressed.Value / recentEvents.Count).ToString("F4"),
                            ["AnalysisType"] = "KeyRepetition"
                        }
                    });
                }
            }
        }

        private void DetectCorrelatedBehavior(List<DetectionResult> results)
        {
            foreach (KeyValuePair<int, BehaviorProfile> entry in _behaviorProfiles)
            {
                BehaviorProfile profile = entry.Value;

                if (profile.Observations.Count < 30)
                    continue;

                try
                {
                    double[] cpuValues = profile.Observations.Select(o => o.CpuTime).ToArray();
                    double[] memoryValues = profile.Observations.Select(o => (double)o.MemoryUsage).ToArray();
                    double[] threadValues = profile.Observations.Select(o => (double)o.ThreadCount).ToArray();

                    double cpuMemoryCorrelation = CalculatePearsonCorrelation(cpuValues, memoryValues);
                    double cpuThreadCorrelation = CalculatePearsonCorrelation(cpuValues, threadValues);

                    if (Math.Abs(cpuMemoryCorrelation) > CORRELATION_THRESHOLD)
                    {
                        results.Add(new DetectionResult
                        {
                            Type = DetectionType.Activity,
                            Level = ThreatLevel.Medium,
                            Description = $"Unusual CPU-Memory correlation: {profile.ProcessName}",
                            Details = $"Process ID: {profile.ProcessId}, Correlation: {cpuMemoryCorrelation:F4}",
                            Metadata = new Dictionary<string, string>
                            {
                                ["ProcessName"] = profile.ProcessName,
                                ["ProcessId"] = profile.ProcessId.ToString(),
                                ["Correlation"] = cpuMemoryCorrelation.ToString("F6"),
                                ["CorrelationType"] = "CPU-Memory",
                                ["AnalysisType"] = "PearsonCorrelation"
                            }
                        });
                    }

                    if (Math.Abs(cpuThreadCorrelation) > CORRELATION_THRESHOLD)
                    {
                        results.Add(new DetectionResult
                        {
                            Type = DetectionType.Activity,
                            Level = ThreatLevel.Medium,
                            Description = $"Unusual CPU-Thread correlation: {profile.ProcessName}",
                            Details = $"Process ID: {profile.ProcessId}, Correlation: {cpuThreadCorrelation:F4}",
                            Metadata = new Dictionary<string, string>
                            {
                                ["ProcessName"] = profile.ProcessName,
                                ["ProcessId"] = profile.ProcessId.ToString(),
                                ["Correlation"] = cpuThreadCorrelation.ToString("F6"),
                                ["CorrelationType"] = "CPU-Threads",
                                ["AnalysisType"] = "PearsonCorrelation"
                            }
                        });
                    }
                }
                catch
                {
                }
            }
        }

        private void RecordInputEvents()
        {
            LASTINPUTINFO lastInput = new()
            {
                cbSize = (uint)Marshal.SizeOf(typeof(LASTINPUTINFO))
            };

            if (GetLastInputInfo(ref lastInput))
            {
                uint idleTime = (uint)Environment.TickCount - lastInput.dwTime;

                if (idleTime < 100)
                {
                    for (int keyCode = 0; keyCode < 256; keyCode++)
                    {
                        short keyState = GetAsyncKeyState(keyCode);
                        if ((keyState & 0x8000) != 0)
                        {
                            _inputHistory.Add(new InputEvent
                            {
                                Timestamp = DateTime.UtcNow,
                                KeyCode = keyCode
                            });

                            if (_inputHistory.Count > MAX_INPUT_HISTORY)
                            {
                                _inputHistory.RemoveAt(0);
                            }

                            break;
                        }
                    }
                }
            }
        }

        private static double CalculateVariance(double[] values)
        {
            if (values.Length < 2)
                return 0;

            double mean = values.Average();
            double sumSquaredDifferences = values.Sum(v => Math.Pow(v - mean, 2));
            return sumSquaredDifferences / values.Length;
        }

        private static double CalculateStandardDeviation(double[] values, double mean)
        {
            if (values.Length < 2)
                return 0;

            double sumSquaredDifferences = values.Sum(v => Math.Pow(v - mean, 2));
            return Math.Sqrt(sumSquaredDifferences / values.Length);
        }

        private static double CalculatePearsonCorrelation(double[] x, double[] y)
        {
            if (x.Length != y.Length || x.Length < 2)
                return 0;

            double meanX = x.Average();
            double meanY = y.Average();

            double numerator = 0;
            double sumXSquared = 0;
            double sumYSquared = 0;

            for (int i = 0; i < x.Length; i++)
            {
                double diffX = x[i] - meanX;
                double diffY = y[i] - meanY;

                numerator += diffX * diffY;
                sumXSquared += diffX * diffX;
                sumYSquared += diffY * diffY;
            }

            double denominator = Math.Sqrt(sumXSquared * sumYSquared);

            if (denominator == 0)
                return 0;

            return numerator / denominator;
        }

        private sealed class BehaviorProfile
        {
            public int ProcessId { get; init; }
            public string ProcessName { get; init; } = string.Empty;
            public DateTime StartTime { get; init; }
            public List<BehaviorObservation> Observations { get; init; } = [];
        }

        private sealed class BehaviorObservation
        {
            public DateTime Timestamp { get; init; }
            public double CpuTime { get; init; }
            public long MemoryUsage { get; init; }
            public int ThreadCount { get; init; }
            public int HandleCount { get; init; }
        }

        private sealed class InputEvent
        {
            public DateTime Timestamp { get; init; }
            public int KeyCode { get; init; }
        }
    }
}