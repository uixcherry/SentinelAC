using SentinelAC.Core.Interfaces;
using SentinelAC.Core.Models;
using System.Diagnostics;

namespace SentinelAC.Detectors
{
    public sealed class StatisticalAnomalyDetector : IDetector
    {
        public DetectionType Type => DetectionType.Process;
        public bool RequiresAdminRights => false;

        private readonly Dictionary<string, List<ProcessMetrics>> _processHistory;
        private const int SAMPLE_SIZE = 50;
        private const double Z_SCORE_THRESHOLD = 2.5;
        private const double ENTROPY_THRESHOLD = 3.5;

        public StatisticalAnomalyDetector()
        {
            _processHistory = [];
        }

        public async Task<List<DetectionResult>> ScanAsync()
        {
            return await Task.Run(() =>
            {
                List<DetectionResult> results = [];

                CollectProcessMetrics();
                DetectEntropyAnomalies(results);
                DetectStatisticalOutliers(results);
                DetectBayesianAnomalies(results);

                return results;
            });
        }

        private void CollectProcessMetrics()
        {
            Process[] processes = Process.GetProcesses();

            foreach (Process process in processes)
            {
                try
                {
                    string processName = process.ProcessName;

                    if (!_processHistory.ContainsKey(processName))
                    {
                        _processHistory[processName] = new List<ProcessMetrics>();
                    }

                    ProcessMetrics metrics = new()
                    {
                        ProcessName = processName,
                        ProcessId = process.Id,
                        CpuTime = process.TotalProcessorTime.TotalMilliseconds,
                        MemoryUsage = process.WorkingSet64,
                        ThreadCount = process.Threads.Count,
                        HandleCount = process.HandleCount,
                        Timestamp = DateTime.UtcNow
                    };

                    List<ProcessMetrics> history = _processHistory[processName];
                    history.Add(metrics);

                    if (history.Count > SAMPLE_SIZE)
                    {
                        history.RemoveAt(0);
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

        private void DetectEntropyAnomalies(List<DetectionResult> results)
        {
            foreach (KeyValuePair<string, List<ProcessMetrics>> entry in _processHistory)
            {
                if (entry.Value.Count < 10)
                    continue;

                try
                {
                    double entropy = CalculateEntropy(entry.Key);

                    if (entropy > ENTROPY_THRESHOLD)
                    {
                        ProcessMetrics latest = entry.Value[^1];

                        results.Add(new DetectionResult
                        {
                            Type = DetectionType.Process,
                            Level = ThreatLevel.Medium,
                            Description = $"High entropy detected in process name: {entry.Key}",
                            Details = $"Process ID: {latest.ProcessId}, Entropy: {entropy:F2} (Threshold: {ENTROPY_THRESHOLD})",
                            Metadata = new Dictionary<string, string>
                            {
                                ["ProcessName"] = entry.Key,
                                ["ProcessId"] = latest.ProcessId.ToString(),
                                ["Entropy"] = entropy.ToString("F4"),
                                ["Threshold"] = ENTROPY_THRESHOLD.ToString("F2"),
                                ["AnalysisType"] = "ShannonEntropy"
                            }
                        });
                    }
                }
                catch
                {
                }
            }
        }

        private void DetectStatisticalOutliers(List<DetectionResult> results)
        {
            foreach (KeyValuePair<string, List<ProcessMetrics>> entry in _processHistory)
            {
                if (entry.Value.Count < 20)
                    continue;

                try
                {
                    ProcessMetrics latest = entry.Value[^1];
                    double[] memoryValues = entry.Value.Select(m => (double)m.MemoryUsage).ToArray();
                    double[] threadValues = entry.Value.Select(m => (double)m.ThreadCount).ToArray();

                    double memoryMean = CalculateMean(memoryValues);
                    double memoryStdDev = CalculateStandardDeviation(memoryValues, memoryMean);
                    double memoryZScore = Math.Abs((latest.MemoryUsage - memoryMean) / memoryStdDev);

                    double threadMean = CalculateMean(threadValues);
                    double threadStdDev = CalculateStandardDeviation(threadValues, threadMean);
                    double threadZScore = Math.Abs((latest.ThreadCount - threadMean) / threadStdDev);

                    if (memoryZScore > Z_SCORE_THRESHOLD)
                    {
                        results.Add(new DetectionResult
                        {
                            Type = DetectionType.Process,
                            Level = ThreatLevel.High,
                            Description = $"Abnormal memory usage pattern: {entry.Key}",
                            Details = $"Process ID: {latest.ProcessId}, Z-Score: {memoryZScore:F2}, Memory: {latest.MemoryUsage / (1024 * 1024)}MB",
                            Metadata = new Dictionary<string, string>
                            {
                                ["ProcessName"] = entry.Key,
                                ["ProcessId"] = latest.ProcessId.ToString(),
                                ["ZScore"] = memoryZScore.ToString("F4"),
                                ["MemoryMB"] = (latest.MemoryUsage / (1024 * 1024)).ToString("F2"),
                                ["MeanMemoryMB"] = (memoryMean / (1024 * 1024)).ToString("F2"),
                                ["StdDevMemoryMB"] = (memoryStdDev / (1024 * 1024)).ToString("F2"),
                                ["AnalysisType"] = "ZScoreMemory"
                            }
                        });
                    }

                    if (threadZScore > Z_SCORE_THRESHOLD)
                    {
                        results.Add(new DetectionResult
                        {
                            Type = DetectionType.Process,
                            Level = ThreatLevel.Medium,
                            Description = $"Abnormal thread count pattern: {entry.Key}",
                            Details = $"Process ID: {latest.ProcessId}, Z-Score: {threadZScore:F2}, Threads: {latest.ThreadCount}",
                            Metadata = new Dictionary<string, string>
                            {
                                ["ProcessName"] = entry.Key,
                                ["ProcessId"] = latest.ProcessId.ToString(),
                                ["ZScore"] = threadZScore.ToString("F4"),
                                ["ThreadCount"] = latest.ThreadCount.ToString(),
                                ["MeanThreads"] = threadMean.ToString("F2"),
                                ["StdDevThreads"] = threadStdDev.ToString("F2"),
                                ["AnalysisType"] = "ZScoreThreads"
                            }
                        });
                    }
                }
                catch
                {
                }
            }
        }

        private void DetectBayesianAnomalies(List<DetectionResult> results)
        {
            double priorMalicious = 0.05;
            double priorBenign = 0.95;

            foreach (KeyValuePair<string, List<ProcessMetrics>> entry in _processHistory)
            {
                if (entry.Value.Count < 15)
                    continue;

                try
                {
                    ProcessMetrics latest = entry.Value[^1];

                    double highMemoryLikelihoodMalicious = 0.7;
                    double highMemoryLikelihoodBenign = 0.2;

                    double highThreadsLikelihoodMalicious = 0.6;
                    double highThreadsLikelihoodBenign = 0.3;

                    bool highMemory = latest.MemoryUsage > 500 * 1024 * 1024;
                    bool highThreads = latest.ThreadCount > 50;

                    double likelihoodMalicious = priorMalicious;
                    double likelihoodBenign = priorBenign;

                    if (highMemory)
                    {
                        double evidenceMemory = (highMemoryLikelihoodMalicious * priorMalicious) +
                                               (highMemoryLikelihoodBenign * priorBenign);

                        likelihoodMalicious = (highMemoryLikelihoodMalicious * likelihoodMalicious) / evidenceMemory;
                        likelihoodBenign = (highMemoryLikelihoodBenign * likelihoodBenign) / evidenceMemory;
                    }

                    if (highThreads)
                    {
                        double evidenceThreads = (highThreadsLikelihoodMalicious * likelihoodMalicious) +
                                                (highThreadsLikelihoodBenign * likelihoodBenign);

                        likelihoodMalicious = (highThreadsLikelihoodMalicious * likelihoodMalicious) / evidenceThreads;
                        likelihoodBenign = (highThreadsLikelihoodBenign * likelihoodBenign) / evidenceThreads;
                    }

                    double posteriorMalicious = likelihoodMalicious / (likelihoodMalicious + likelihoodBenign);

                    if (posteriorMalicious > 0.7)
                    {
                        results.Add(new DetectionResult
                        {
                            Type = DetectionType.Process,
                            Level = ThreatLevel.High,
                            Description = $"Bayesian analysis indicates high malicious probability: {entry.Key}",
                            Details = $"Process ID: {latest.ProcessId}, Probability: {posteriorMalicious:P2}",
                            Metadata = new Dictionary<string, string>
                            {
                                ["ProcessName"] = entry.Key,
                                ["ProcessId"] = latest.ProcessId.ToString(),
                                ["MaliciousProbability"] = posteriorMalicious.ToString("F4"),
                                ["HighMemory"] = highMemory.ToString(),
                                ["HighThreads"] = highThreads.ToString(),
                                ["AnalysisType"] = "BayesianClassification"
                            }
                        });
                    }
                }
                catch
                {
                }
            }
        }

        private static double CalculateEntropy(string text)
        {
            if (string.IsNullOrEmpty(text))
                return 0;

            Dictionary<char, int> frequency = [];

            foreach (char c in text)
            {
                if (!frequency.ContainsKey(c))
                    frequency[c] = 0;
                frequency[c]++;
            }

            double entropy = 0;
            int length = text.Length;

            foreach (int count in frequency.Values)
            {
                double probability = (double)count / length;
                entropy -= probability * Math.Log2(probability);
            }

            return entropy;
        }

        private static double CalculateMean(double[] values)
        {
            if (values.Length == 0)
                return 0;

            double sum = 0;
            foreach (double value in values)
            {
                sum += value;
            }

            return sum / values.Length;
        }

        private static double CalculateStandardDeviation(double[] values, double mean)
        {
            if (values.Length == 0)
                return 0;

            double sumSquaredDifferences = 0;

            foreach (double value in values)
            {
                double difference = value - mean;
                sumSquaredDifferences += difference * difference;
            }

            return Math.Sqrt(sumSquaredDifferences / values.Length);
        }

        private sealed class ProcessMetrics
        {
            public string ProcessName { get; init; } = string.Empty;
            public int ProcessId { get; init; }
            public double CpuTime { get; init; }
            public long MemoryUsage { get; init; }
            public int ThreadCount { get; init; }
            public int HandleCount { get; init; }
            public DateTime Timestamp { get; init; }
        }
    }
}