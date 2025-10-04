using SentinelAC.Core.Models;

namespace SentinelAC.Core.Interfaces
{
    public interface IDetector
    {
        DetectionType Type { get; }
        Task<List<DetectionResult>> ScanAsync();
        bool RequiresAdminRights { get; }
    }

    public interface ISignatureDatabase
    {
        bool IsKnownThreat(string name);
        bool IsSuspiciousPattern(string name);
        void LoadSignatures();
        void UpdateSignatures();
    }

    public interface IReportGenerator
    {
        void GenerateConsoleReport(ScanReport report);
        Task SaveReportAsync(ScanReport report, string path);
    }

    public interface IScanEngine
    {
        Task<ScanReport> ExecuteFullScanAsync();
        void RegisterDetector(IDetector detector);
    }
}