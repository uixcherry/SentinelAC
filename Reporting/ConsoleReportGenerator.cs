using SentinelAC.Core.Interfaces;
using SentinelAC.Core.Models;
using System.Text;

namespace SentinelAC.Reporting
{
    public sealed class ConsoleReportGenerator : IReportGenerator
    {
        public void GenerateConsoleReport(ScanReport report)
        {
            Console.WriteLine("═══════════════════════════════════════════════════════════════");
            Console.WriteLine("                    SENTINEL AC - SCAN REPORT                  ");
            Console.WriteLine("═══════════════════════════════════════════════════════════════");
            Console.WriteLine();

            Console.WriteLine($"Scan Started:        {report.ScanStarted:yyyy-MM-dd HH:mm:ss} UTC");
            Console.WriteLine($"Scan Completed:      {report.ScanCompleted:yyyy-MM-dd HH:mm:ss} UTC");
            Console.WriteLine($"Duration:            {report.Duration.TotalSeconds:F2} seconds");
            Console.WriteLine($"Total Checks:        {report.TotalChecks}");
            Console.WriteLine();

            ConsoleColor originalColor = Console.ForegroundColor;
            Console.Write("Overall Threat Level: ");
            Console.ForegroundColor = GetThreatLevelColor(report.OverallThreatLevel);
            Console.WriteLine($"{report.OverallThreatLevel}");
            Console.ForegroundColor = originalColor;
            Console.WriteLine();

            if (report.IsClean)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("✓ System appears clean - No significant threats detected");
                Console.ForegroundColor = originalColor;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"⚠ {report.Detections.Count} threat(s) detected!");
                Console.ForegroundColor = originalColor;
            }

            Console.WriteLine();
            Console.WriteLine("───────────────────────────────────────────────────────────────");
            Console.WriteLine("                        DETECTIONS                             ");
            Console.WriteLine("───────────────────────────────────────────────────────────────");
            Console.WriteLine();

            Dictionary<DetectionType, List<DetectionResult>> groupedDetections = report.Detections
                .GroupBy(d => d.Type)
                .ToDictionary(g => g.Key, g => g.ToList());

            foreach (KeyValuePair<DetectionType, List<DetectionResult>> group in groupedDetections.OrderByDescending(g => g.Value.Max(d => d.Level)))
            {
                Console.WriteLine($"▼ {group.Key} ({group.Value.Count} detection(s))");
                Console.WriteLine();

                foreach (DetectionResult detection in group.Value.OrderByDescending(d => d.Level))
                {
                    Console.Write("  [");
                    Console.ForegroundColor = GetThreatLevelColor(detection.Level);
                    Console.Write(detection.Level.ToString().ToUpper());
                    Console.ForegroundColor = originalColor;
                    Console.WriteLine("]");

                    Console.WriteLine($"  Description: {detection.Description}");
                    Console.WriteLine($"  Details:     {detection.Details}");
                    Console.WriteLine($"  Detected:    {detection.DetectedAt:yyyy-MM-dd HH:mm:ss} UTC");

                    if (detection.Metadata.Any())
                    {
                        Console.WriteLine("  Metadata:");
                        foreach (KeyValuePair<string, string> meta in detection.Metadata)
                        {
                            Console.WriteLine($"    - {meta.Key}: {meta.Value}");
                        }
                    }

                    Console.WriteLine();
                }
            }

            Console.WriteLine("═══════════════════════════════════════════════════════════════");
            Console.WriteLine("                      END OF REPORT                            ");
            Console.WriteLine("═══════════════════════════════════════════════════════════════");
        }

        public async Task SaveReportAsync(ScanReport report, string path)
        {
            StringBuilder sb = new();

            sb.AppendLine("═══════════════════════════════════════════════════════════════");
            sb.AppendLine("                    SENTINEL AC - SCAN REPORT                  ");
            sb.AppendLine("═══════════════════════════════════════════════════════════════");
            sb.AppendLine();

            sb.AppendLine($"Scan Started:        {report.ScanStarted:yyyy-MM-dd HH:mm:ss} UTC");
            sb.AppendLine($"Scan Completed:      {report.ScanCompleted:yyyy-MM-dd HH:mm:ss} UTC");
            sb.AppendLine($"Duration:            {report.Duration.TotalSeconds:F2} seconds");
            sb.AppendLine($"Total Checks:        {report.TotalChecks}");
            sb.AppendLine($"Overall Threat Level: {report.OverallThreatLevel}");
            sb.AppendLine();

            if (report.IsClean)
            {
                sb.AppendLine("✓ System appears clean - No significant threats detected");
            }
            else
            {
                sb.AppendLine($"⚠ {report.Detections.Count} threat(s) detected!");
            }

            sb.AppendLine();
            sb.AppendLine("───────────────────────────────────────────────────────────────");
            sb.AppendLine("                        DETECTIONS                             ");
            sb.AppendLine("───────────────────────────────────────────────────────────────");
            sb.AppendLine();

            Dictionary<DetectionType, List<DetectionResult>> groupedDetections = report.Detections
                .GroupBy(d => d.Type)
                .ToDictionary(g => g.Key, g => g.ToList());

            foreach (KeyValuePair<DetectionType, List<DetectionResult>> group in groupedDetections.OrderByDescending(g => g.Value.Max(d => d.Level)))
            {
                sb.AppendLine($"▼ {group.Key} ({group.Value.Count} detection(s))");
                sb.AppendLine();

                foreach (DetectionResult detection in group.Value.OrderByDescending(d => d.Level))
                {
                    sb.AppendLine($"  [{detection.Level.ToString().ToUpper()}]");
                    sb.AppendLine($"  Description: {detection.Description}");
                    sb.AppendLine($"  Details:     {detection.Details}");
                    sb.AppendLine($"  Detected:    {detection.DetectedAt:yyyy-MM-dd HH:mm:ss} UTC");

                    if (detection.Metadata.Any())
                    {
                        sb.AppendLine("  Metadata:");
                        foreach (KeyValuePair<string, string> meta in detection.Metadata)
                        {
                            sb.AppendLine($"    - {meta.Key}: {meta.Value}");
                        }
                    }

                    sb.AppendLine();
                }
            }

            sb.AppendLine("═══════════════════════════════════════════════════════════════");
            sb.AppendLine("                      END OF REPORT                            ");
            sb.AppendLine("═══════════════════════════════════════════════════════════════");

            await File.WriteAllTextAsync(path, sb.ToString());
        }

        private ConsoleColor GetThreatLevelColor(ThreatLevel level)
        {
            return level switch
            {
                ThreatLevel.Critical => ConsoleColor.Red,
                ThreatLevel.High => ConsoleColor.DarkRed,
                ThreatLevel.Medium => ConsoleColor.Yellow,
                ThreatLevel.Low => ConsoleColor.DarkYellow,
                ThreatLevel.None => ConsoleColor.Green,
                _ => ConsoleColor.White
            };
        }
    }
}