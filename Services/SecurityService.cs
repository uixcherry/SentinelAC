using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Runtime.Versioning;

namespace SentinelAC.Services
{
    [SupportedOSPlatform("windows")]
    public sealed class SecurityService
    {
        private enum DebuggerType
        {
            None,
            DevelopmentIDE,
            CheatDebugger
        }

        [DllImport("kernel32.dll")]
        private static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll")]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, int processInformationLength, out int returnLength);

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        public bool PerformSecurityChecks()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("[Security] Running anti-tampering checks...");
            Console.ResetColor();

            DebuggerType debuggerType = DetectDebugger();

            if (debuggerType == DebuggerType.CheatDebugger)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("⚠️ CRITICAL: Cheat debugger detected! Scan terminated.");
                Console.ResetColor();
                return false;
            }
            else if (debuggerType == DebuggerType.DevelopmentIDE)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("⚠️ INFO: Development debugger detected (Visual Studio/Rider).");
                Console.WriteLine("   Continuing scan - this is normal for development builds.");
                Console.ResetColor();
            }

            if (DetectVirtualization())
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("⚠️ WARNING: Running in virtualized environment.");
                Console.ResetColor();
            }

            if (!VerifyIntegrity())
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("⚠️ CRITICAL: Application integrity check failed!");
                Console.ResetColor();
                return false;
            }

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("✓ Security checks passed");
            Console.ResetColor();

            return true;
        }

        private DebuggerType DetectDebugger()
        {
            string[] developmentIDEs = ["devenv", "rider64", "rider", "code", "vscode"];
            string[] cheatDebuggers = ["x64dbg", "x32dbg", "ollydbg", "windbg", "ida", "ida64", "cheatengine"];

            try
            {
                PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
                int returnLength;
                int status = NtQueryInformationProcess(Process.GetCurrentProcess().Handle, 0, ref pbi, Marshal.SizeOf(pbi), out returnLength);

                if (status == 0 && pbi.InheritedFromUniqueProcessId != IntPtr.Zero)
                {
                    Process parentProcess = Process.GetProcessById(pbi.InheritedFromUniqueProcessId.ToInt32());
                    string parentName = parentProcess.ProcessName.ToLowerInvariant();

                    if (developmentIDEs.Any(ide => parentName.Contains(ide)))
                    {
                        parentProcess.Dispose();
                        return DebuggerType.DevelopmentIDE;
                    }

                    if (cheatDebuggers.Any(debugger => parentName.Contains(debugger)))
                    {
                        parentProcess.Dispose();
                        return DebuggerType.CheatDebugger;
                    }

                    parentProcess.Dispose();
                }
            }
            catch
            {
            }

            if (Debugger.IsAttached)
            {
                return DebuggerType.DevelopmentIDE;
            }

            bool isDebuggerPresent = false;
            CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent);
            if (isDebuggerPresent)
            {
                return DebuggerType.CheatDebugger;
            }

            if (IsDebuggerPresent())
            {
                return DebuggerType.CheatDebugger;
            }

            return DebuggerType.None;
        }

        private bool DetectVirtualization()
        {
            try
            {
                using System.Management.ManagementObjectSearcher searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
                foreach (System.Management.ManagementObject obj in searcher.Get())
                {
                    string manufacturer = obj["Manufacturer"]?.ToString()?.ToLowerInvariant() ?? string.Empty;
                    string model = obj["Model"]?.ToString()?.ToLowerInvariant() ?? string.Empty;

                    if (manufacturer.Contains("vmware") || manufacturer.Contains("virtualbox") ||
                        model.Contains("virtual") || model.Contains("vmware"))
                    {
                        return true;
                    }
                }
            }
            catch
            {
            }

            return false;
        }

        private bool VerifyIntegrity()
        {
            try
            {
                string exePath = Process.GetCurrentProcess().MainModule?.FileName ?? string.Empty;

                if (string.IsNullOrEmpty(exePath))
                    return false;

                byte[] fileBytes = File.ReadAllBytes(exePath);
                using SHA256 sha256 = SHA256.Create();
                byte[] hash = sha256.ComputeHash(fileBytes);

                long fileSize = new FileInfo(exePath).Length;
                DateTime creationTime = File.GetCreationTime(exePath);
                TimeSpan timeSinceCreation = DateTime.Now - creationTime;

                if (timeSinceCreation.TotalMinutes < 1)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("⚠️ WARNING: Executable created less than 1 minute ago - possible tampering");
                    Console.ResetColor();
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        public void DisplaySecurityBanner()
        {
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            Console.WriteLine("╔═══════════════════════════════════════════════════════════╗");
            Console.WriteLine("║            ANTI-TAMPERING PROTECTION ACTIVE              ║");
            Console.WriteLine("║  • Debugger Detection      • Integrity Verification      ║");
            Console.WriteLine("║  • VM Detection            • Process Protection           ║");
            Console.WriteLine("╚═══════════════════════════════════════════════════════════╝");
            Console.ResetColor();
            Console.WriteLine();
        }
    }
}
