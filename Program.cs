using SentinelAC.Core.Data;
using SentinelAC.Core.Interfaces;
using SentinelAC.Core.Models;
using SentinelAC.Detectors;
using SentinelAC.Reporting;
using SentinelAC.Services;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace SentinelAC
{
    [SupportedOSPlatform("windows")]
    public sealed class Program
    {
        private static bool IsAdministrator()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        private static void PrintBanner()
        {
            Console.Clear();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(@"
    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗          █████╗  ██████╗
    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║         ██╔══██╗██╔════╝
    ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║         ███████║██║     
    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║         ██╔══██║██║     
    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗    ██║  ██║╚██████╗
    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝    ╚═╝  ╚═╝ ╚═════╝
                                                                                          
                        Advanced Anti-Cheat Detection System v1.2
            ");
            Console.ResetColor();
            Console.WriteLine();
        }

        private static void PrintSystemInfo()
        {
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine($"OS:                  {Environment.OSVersion}");
            Console.WriteLine($"Machine:             {Environment.MachineName}");
            Console.WriteLine($"User:                {Environment.UserName}");
            Console.WriteLine($"Processors:          {Environment.ProcessorCount}");
            Console.WriteLine($"Admin Rights:        {(IsAdministrator() ? "Yes" : "No")}");
            Console.WriteLine($".NET Version:        {Environment.Version}");
            Console.ResetColor();
            Console.WriteLine();
        }

        public static async Task Main(string[] args)
        {
            try
            {
                PrintBanner();

                SecurityService securityService = new SecurityService();
                securityService.DisplaySecurityBanner();

                if (!securityService.PerformSecurityChecks())
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n✗ Security checks failed. Scan terminated.");
                    Console.WriteLine("This may indicate tampering or debugging attempts.");
                    Console.ResetColor();
                    Console.WriteLine("\nPress any key to exit...");
                    Console.ReadKey(true);
                    return;
                }

                Console.WriteLine();
                PrintSystemInfo();

                if (!IsAdministrator())
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("⚠ WARNING: Running without administrator privileges.");
                    Console.WriteLine("Some detectors may not function properly.");
                    Console.WriteLine("For best results, run as administrator.");
                    Console.ResetColor();
                    Console.WriteLine();
                }

                Console.WriteLine("Press any key to start the scan...");
                Console.ReadKey(true);
                Console.WriteLine();

                ISignatureDatabase signatureDatabase = new SignatureDatabase();
                WhitelistDatabase whitelistDatabase = new();

                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Initializing detection modules...");
                Console.WriteLine();

                ScanEngine scanEngine = new();
                scanEngine.RegisterDetector(new ProcessDetector(signatureDatabase, whitelistDatabase));
                scanEngine.RegisterDetector(new ModuleDetector(signatureDatabase, whitelistDatabase));
                scanEngine.RegisterDetector(new DriverDetector(signatureDatabase, whitelistDatabase));
                scanEngine.RegisterDetector(new NetworkDetector());
                scanEngine.RegisterDetector(new FileIntegrityDetector());
                scanEngine.RegisterDetector(new VirtualizationDetector());
                scanEngine.RegisterDetector(new RegistryDetector(signatureDatabase, whitelistDatabase));
                scanEngine.RegisterDetector(new ActivityDetector());
                scanEngine.RegisterDetector(new SteamAccountDetector());
                scanEngine.RegisterDetector(new HardwareProfileDetector());
                scanEngine.RegisterDetector(new InputManipulationDetector());
                scanEngine.RegisterDetector(new ScreenshotBlockerDetector());
                scanEngine.RegisterDetector(new SystemManipulationDetector());
                scanEngine.RegisterDetector(new MemoryScannerDetector());
                scanEngine.RegisterDetector(new SandboxDetector());
                scanEngine.RegisterDetector(new FileSystemDetector(signatureDatabase));
                scanEngine.RegisterDetector(new StatisticalAnomalyDetector());
                scanEngine.RegisterDetector(new BehavioralAnalyzer());
                scanEngine.RegisterDetector(new RegistryCleanerDetector());
                scanEngine.RegisterDetector(new EventLogTamperingDetector());
                scanEngine.RegisterDetector(new AntiForensicsDetector());

                ScanReport report = await scanEngine.ExecuteFullScanAsync();

                IReportGenerator reportGenerator = new ConsoleReportGenerator();
                reportGenerator.GenerateConsoleReport(report);

                Console.WriteLine();
                Console.Write("Send report to Discord? (y/n): ");
                string? discordResponse = Console.ReadLine()?.ToLowerInvariant() ?? "n";

                if (discordResponse == "y" || discordResponse == "yes")
                {
                    Console.WriteLine();
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("Sending report to Discord...");
                    Console.ResetColor();

                    DiscordWebhookService discordService = new DiscordWebhookService();
                    bool sent = await discordService.SendReportAsync(report);

                    if (!sent)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("Failed to send to Discord. Report will be saved locally instead.");
                        Console.ResetColor();
                    }
                }

                Console.WriteLine();
                Console.Write("Would you like to save this report to a file? (y/n): ");
                string? response = Console.ReadLine()?.ToLowerInvariant() ?? "n";

                if (response == "y" || response == "yes")
                {
                    string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                    string fileName = $"SentinelAC_Report_{timestamp}.txt";
                    await reportGenerator.SaveReportAsync(report, fileName);

                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"✓ Report saved to: {Path.GetFullPath(fileName)}");
                    Console.ResetColor();
                }

                Console.WriteLine();
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey(true);
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"✗ Fatal error occurred: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
                Console.ResetColor();
                Console.WriteLine();
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey(true);
            }
        }
    }
}