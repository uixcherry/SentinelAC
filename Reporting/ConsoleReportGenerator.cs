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

            if (report.Detections.Any())
            {
                Console.WriteLine($"Average Confidence:  {report.AverageConfidence:P0}");
                Console.WriteLine($"High Confidence:     {report.HighConfidenceDetections} detection(s)");
                Console.WriteLine($"Possible False Pos:  {report.PossibleFalsePositives} detection(s)");
            }
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

            List<DetectionResult> highConfidence = report.GetHighConfidenceThreats();
            if (highConfidence.Any())
            {
                Console.WriteLine("───────────────────────────────────────────────────────────────");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("              ⚠ HIGH CONFIDENCE THREATS ⚠                     ");
                Console.ForegroundColor = originalColor;
                Console.WriteLine("───────────────────────────────────────────────────────────────");
                Console.WriteLine();

                foreach (DetectionResult detection in highConfidence)
                {
                    PrintDetection(detection, originalColor, highlightMode: true);
                }
            }

            Console.WriteLine("───────────────────────────────────────────────────────────────");
            Console.WriteLine("                        ALL DETECTIONS                         ");
            Console.WriteLine("───────────────────────────────────────────────────────────────");
            Console.WriteLine();

            Dictionary<DetectionType, List<DetectionResult>> groupedDetections = report.Detections
                .GroupBy(d => d.Type)
                .ToDictionary(g => g.Key, g => g.ToList());

            foreach (KeyValuePair<DetectionType, List<DetectionResult>> group in groupedDetections.OrderByDescending(g => g.Value.Max(d => d.Level)))
            {
                Console.WriteLine($"▼ {group.Key} ({group.Value.Count} detection(s))");
                Console.WriteLine();

                foreach (DetectionResult detection in group.Value.OrderByDescending(d => d.Level).ThenByDescending(d => d.ConfidenceScore))
                {
                    PrintDetection(detection, originalColor);
                }
            }

            List<DetectionResult> falsePositives = report.GetPossibleFalsePositives();
            if (falsePositives.Any())
            {
                Console.WriteLine("───────────────────────────────────────────────────────────────");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("              ℹ POSSIBLE FALSE POSITIVES ℹ                    ");
                Console.ForegroundColor = originalColor;
                Console.WriteLine("───────────────────────────────────────────────────────────────");
                Console.WriteLine();

                foreach (DetectionResult detection in falsePositives)
                {
                    PrintDetection(detection, originalColor, showFalsePositiveWarning: true);
                }
            }

            Console.WriteLine("═══════════════════════════════════════════════════════════════");
            Console.WriteLine("                      END OF REPORT                            ");
            Console.WriteLine("═══════════════════════════════════════════════════════════════");
        }

        private static void PrintDetection(DetectionResult detection, ConsoleColor originalColor,
            bool highlightMode = false, bool showFalsePositiveWarning = false)
        {
            if (highlightMode)
                Console.ForegroundColor = ConsoleColor.Red;

            Console.Write("  [");
            Console.ForegroundColor = GetThreatLevelColor(detection.Level);
            Console.Write(detection.Level.ToString().ToUpper());
            Console.ForegroundColor = originalColor;
            Console.Write("] ");

            Console.ForegroundColor = GetConfidenceColor(detection.ConfidenceScore);
            Console.Write($"[{detection.GetConfidenceDisplay()}]");
            Console.ForegroundColor = originalColor;

            if (detection.IsPossiblyFalsePositive && !showFalsePositiveWarning)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write(" [?]");
                Console.ForegroundColor = originalColor;
            }

            Console.WriteLine();

            Console.WriteLine($"  Description: {detection.Description}");
            Console.WriteLine($"  Details:     {detection.Details}");
            Console.WriteLine($"  Detected:    {detection.DetectedAt:yyyy-MM-dd HH:mm:ss} UTC");
            Console.WriteLine($"  Confidence:  {detection.Confidence} ({detection.ConfidenceScore:P0})");

            if (showFalsePositiveWarning)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  ⚠ This detection may be a false positive (low confidence)");
                Console.ForegroundColor = originalColor;
            }

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

            if (report.Detections.Any())
            {
                sb.AppendLine($"Average Confidence:  {report.AverageConfidence:P0}");
                sb.AppendLine($"High Confidence:     {report.HighConfidenceDetections} detection(s)");
                sb.AppendLine($"Possible False Pos:  {report.PossibleFalsePositives} detection(s)");
            }
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

            List<DetectionResult> highConfidence = report.GetHighConfidenceThreats();
            if (highConfidence.Any())
            {
                sb.AppendLine("───────────────────────────────────────────────────────────────");
                sb.AppendLine("              ⚠ HIGH CONFIDENCE THREATS ⚠                     ");
                sb.AppendLine("───────────────────────────────────────────────────────────────");
                sb.AppendLine();

                foreach (DetectionResult detection in highConfidence)
                {
                    AppendDetection(sb, detection);
                }
            }

            sb.AppendLine("───────────────────────────────────────────────────────────────");
            sb.AppendLine("                        ALL DETECTIONS                         ");
            sb.AppendLine("───────────────────────────────────────────────────────────────");
            sb.AppendLine();

            Dictionary<DetectionType, List<DetectionResult>> groupedDetections = report.Detections
                .GroupBy(d => d.Type)
                .ToDictionary(g => g.Key, g => g.ToList());

            foreach (KeyValuePair<DetectionType, List<DetectionResult>> group in groupedDetections.OrderByDescending(g => g.Value.Max(d => d.Level)))
            {
                sb.AppendLine($"▼ {group.Key} ({group.Value.Count} detection(s))");
                sb.AppendLine();

                foreach (DetectionResult detection in group.Value.OrderByDescending(d => d.Level).ThenByDescending(d => d.ConfidenceScore))
                {
                    AppendDetection(sb, detection);
                }
            }

            List<DetectionResult> falsePositives = report.GetPossibleFalsePositives();
            if (falsePositives.Any())
            {
                sb.AppendLine("───────────────────────────────────────────────────────────────");
                sb.AppendLine("              ℹ POSSIBLE FALSE POSITIVES ℹ                    ");
                sb.AppendLine("───────────────────────────────────────────────────────────────");
                sb.AppendLine();

                foreach (DetectionResult detection in falsePositives)
                {
                    AppendDetection(sb, detection, showFalsePositiveWarning: true);
                }
            }

            sb.AppendLine("═══════════════════════════════════════════════════════════════");
            sb.AppendLine("                      END OF REPORT                            ");
            sb.AppendLine("═══════════════════════════════════════════════════════════════");

            await File.WriteAllTextAsync(path, sb.ToString());
        }

        private static void AppendDetection(StringBuilder sb, DetectionResult detection, bool showFalsePositiveWarning = false)
        {
            string fpMarker = detection.IsPossiblyFalsePositive && !showFalsePositiveWarning ? " [?]" : "";
            sb.AppendLine($"  [{detection.Level.ToString().ToUpper()}] [{detection.GetConfidenceDisplay()}]{fpMarker}");
            sb.AppendLine($"  Description: {detection.Description}");
            sb.AppendLine($"  Details:     {detection.Details}");
            sb.AppendLine($"  Detected:    {detection.DetectedAt:yyyy-MM-dd HH:mm:ss} UTC");
            sb.AppendLine($"  Confidence:  {detection.Confidence} ({detection.ConfidenceScore:P0})");

            if (showFalsePositiveWarning)
            {
                sb.AppendLine("  ⚠ This detection may be a false positive (low confidence)");
            }

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

        private static ConsoleColor GetThreatLevelColor(ThreatLevel level)
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

        private static ConsoleColor GetConfidenceColor(double confidence)
        {
            return confidence switch
            {
                >= 0.9 => ConsoleColor.Green,
                >= 0.7 => ConsoleColor.DarkGreen,
                >= 0.5 => ConsoleColor.Yellow,
                >= 0.3 => ConsoleColor.DarkYellow,
                _ => ConsoleColor.Red
            };
        }
    }
}