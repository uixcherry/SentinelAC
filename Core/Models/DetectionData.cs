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

    public sealed class DetectionResult
    {
        public DetectionType Type { get; init; }
        public ThreatLevel Level { get; init; }
        public required string Description { get; init; }
        public required string Details { get; init; }
        public DateTime DetectedAt { get; init; }
        public Dictionary<string, string> Metadata { get; init; }

        public DetectionResult()
        {
            DetectedAt = DateTime.UtcNow;
            Metadata = [];
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
        public bool IsClean => !Detections.Any(d => d.Level >= ThreatLevel.Medium);

        public ScanReport()
        {
            ScanStarted = DateTime.UtcNow;
            Detections = [];
        }
    }
}