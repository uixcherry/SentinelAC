using SentinelAC.Core.Interfaces;
using SentinelAC.Core.Models;

namespace SentinelAC.Services
{
    public sealed class ScanEngine : IScanEngine
    {
        private readonly List<IDetector> _detectors;

        public ScanEngine()
        {
            _detectors = [];
        }

        public void RegisterDetector(IDetector detector)
        {
            _detectors.Add(detector);
        }

        public async Task<ScanReport> ExecuteFullScanAsync()
        {
            ScanReport report = new();
            List<Task<List<DetectionResult>>> tasks = [];

            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Starting comprehensive anti-cheat scan...");
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Registered detectors: {_detectors.Count}");
            Console.WriteLine();

            foreach (IDetector detector in _detectors)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Scanning: {detector.Type}...");
                tasks.Add(detector.ScanAsync());
            }

            List<DetectionResult>[] results = await Task.WhenAll(tasks);

            foreach (List<DetectionResult> detectionList in results)
            {
                report.Detections.AddRange(detectionList);
                report.TotalChecks += detectionList.Count;
            }

            report.ScanCompleted = DateTime.UtcNow;
            report.OverallThreatLevel = CalculateOverallThreatLevel(report.Detections);

            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Scan completed in {report.Duration.TotalSeconds:F2} seconds");
            Console.WriteLine();

            return report;
        }

        private ThreatLevel CalculateOverallThreatLevel(List<DetectionResult> detections)
        {
            if (!detections.Any())
                return ThreatLevel.None;

            if (detections.Any(d => d.Level == ThreatLevel.Critical))
                return ThreatLevel.Critical;

            if (detections.Any(d => d.Level == ThreatLevel.High))
                return ThreatLevel.High;

            if (detections.Any(d => d.Level == ThreatLevel.Medium))
                return ThreatLevel.Medium;

            if (detections.Any(d => d.Level == ThreatLevel.Low))
                return ThreatLevel.Low;

            return ThreatLevel.None;
        }
    }
}