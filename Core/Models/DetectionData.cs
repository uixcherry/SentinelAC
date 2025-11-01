namespace SentinelAC.Core.Models
{
    public enum ThreatLevel
    {
        None,
        Low,
        Medium,
        High,
        Critical
    }

    public enum DetectionType
    {
        Process,
        Module,
        Driver,
        Network,
        FileIntegrity,
        Virtualization,
        Registry,
        Activity,
        SteamAccounts,
        HardwareProfile,
        InputManipulation,
        ScreenshotBlocker,
        SystemManipulation,
        MemoryScanner,
        Sandbox
    }

    public enum ConfidenceLevel
    {
        VeryLow,    // 0-20%
        Low,        // 20-40%
        Medium,     // 40-60%
        High,       // 60-80%
        VeryHigh,   // 80-100%
        Certain     // 100%
    }

    public sealed class DetectionResult
    {
        public DetectionType Type { get; init; }
        public ThreatLevel Level { get; init; }
        public required string Description { get; init; }
        public required string Details { get; init; }
        public DateTime DetectedAt { get; init; }
        public Dictionary<string, string> Metadata { get; init; }

        public double ConfidenceScore { get; init; } = 1.0; // 0.0 - 1.0
        public ConfidenceLevel Confidence => CalculateConfidenceLevel();
        public bool IsPossiblyFalsePositive => ConfidenceScore < 0.6 && Level <= ThreatLevel.Medium;

        public DetectionResult()
        {
            DetectedAt = DateTime.UtcNow;
            Metadata = [];
        }

        private ConfidenceLevel CalculateConfidenceLevel()
        {
            return ConfidenceScore switch
            {
                >= 1.0 => ConfidenceLevel.Certain,
                >= 0.8 => ConfidenceLevel.VeryHigh,
                >= 0.6 => ConfidenceLevel.High,
                >= 0.4 => ConfidenceLevel.Medium,
                >= 0.2 => ConfidenceLevel.Low,
                _ => ConfidenceLevel.VeryLow
            };
        }

        public string GetConfidenceDisplay()
        {
            return Confidence switch
            {
                ConfidenceLevel.Certain => "100%",
                ConfidenceLevel.VeryHigh => $"{ConfidenceScore:P0}",
                ConfidenceLevel.High => $"{ConfidenceScore:P0}",
                ConfidenceLevel.Medium => $"{ConfidenceScore:P0}",
                ConfidenceLevel.Low => $"{ConfidenceScore:P0}",
                ConfidenceLevel.VeryLow => $"{ConfidenceScore:P0}",
                _ => "Unknown"
            };
        }
    }

    public sealed class ScanReport
    {
        public DateTime ScanStarted { get; init; }
        public DateTime ScanCompleted { get; set; }
        public TimeSpan Duration => ScanCompleted - ScanStarted;
        public List<DetectionResult> Detections { get; init; }
        public ThreatLevel OverallThreatLevel { get; set; }
        public int TotalChecks { get; set; }
        public bool IsClean => !Detections.Any(d => d.Level >= ThreatLevel.Medium && !d.IsPossiblyFalsePositive);

        public int HighConfidenceDetections => Detections.Count(d => d.ConfidenceScore >= 0.8);
        public int PossibleFalsePositives => Detections.Count(d => d.IsPossiblyFalsePositive);
        public double AverageConfidence => Detections.Any() ? Detections.Average(d => d.ConfidenceScore) : 0;

        public ScanReport()
        {
            ScanStarted = DateTime.UtcNow;
            Detections = [];
        }

        public List<DetectionResult> GetHighConfidenceThreats()
        {
            return Detections
                .Where(d => d.ConfidenceScore >= 0.8 && d.Level >= ThreatLevel.Medium)
                .OrderByDescending(d => d.Level)
                .ThenByDescending(d => d.ConfidenceScore)
                .ToList();
        }

        public List<DetectionResult> GetPossibleFalsePositives()
        {
            return Detections
                .Where(d => d.IsPossiblyFalsePositive)
                .OrderBy(d => d.ConfidenceScore)
                .ToList();
        }
    }
}