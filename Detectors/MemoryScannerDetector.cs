using SentinelAC.Core.Interfaces;
using SentinelAC.Core.Models;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace SentinelAC.Detectors
{
    [SupportedOSPlatform("windows")]
    public sealed class MemoryScannerDetector : IDetector
    {
        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint MEM_COMMIT = 0x1000;
        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;

        public DetectionType Type => DetectionType.MemoryScanner;
        public bool RequiresAdminRights => false;

        private readonly Dictionary<string, byte[]> _cheatSignatures = new()
        {
            ["CheatEngine_String1"] = Encoding.ASCII.GetBytes("Cheat Engine"),
            ["CheatEngine_String2"] = Encoding.ASCII.GetBytes("CESERVER"),
            ["CheatEngine_String3"] = Encoding.ASCII.GetBytes("speedhack"),
            ["CheatEngine_String4"] = Encoding.ASCII.GetBytes("Dark Byte"),

            ["CE_Pattern1"] = [0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x8B, 0x40, 0x0C],
            ["CE_Pattern2"] = [0x8B, 0x4D, 0xFC, 0x8B, 0x01, 0xFF, 0x50, 0x08],

            ["ArtMoney_String"] = Encoding.ASCII.GetBytes("ArtMoney"),

            ["GameHacker_String"] = Encoding.ASCII.GetBytes("gamehack"),

            ["Injection_LoadLibrary"] = [0x68, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0],

            ["MemScan_Pattern1"] = [0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0x05],
        };

        private readonly string[] _suspiciousWindowTitles =
        [
            "cheat engine", "memory editor", "artmoney", "game hacker",
            "memory scanner", "process hacker", "memory viewer", "hex editor"
        ];

        public async Task<List<DetectionResult>> ScanAsync()
        {
            return await Task.Run(() =>
            {
                List<DetectionResult> results = [];
                Process[] processes = Process.GetProcesses();

                foreach (Process process in processes)
                {
                    try
                    {
                        if (IsMemoryScannerProcess(process))
                        {
                            results.Add(new DetectionResult
                            {
                                Type = DetectionType.MemoryScanner,
                                Level = ThreatLevel.Critical,
                                Description = $"Memory scanner detected: {process.ProcessName}",
                                Details = $"Process ID: {process.Id}, Window: {GetMainWindowTitle(process)}",
                                ConfidenceScore = 0.95,
                                Metadata = new Dictionary<string, string>
                                {
                                    ["ProcessName"] = process.ProcessName,
                                    ["ProcessId"] = process.Id.ToString(),
                                    ["WindowTitle"] = GetMainWindowTitle(process)
                                }
                            });
                        }

                        if (IsSuspiciousForMemoryScan(process))
                        {
                            if (ScanProcessMemoryForSignatures(process, out string foundSignature, out double confidence))
                            {
                                results.Add(new DetectionResult
                                {
                                    Type = DetectionType.MemoryScanner,
                                    Level = DetermineThreatLevel(confidence),
                                    Description = $"Cheat signature found in memory: {process.ProcessName}",
                                    Details = $"Process ID: {process.Id}, Signature: {foundSignature}",
                                    ConfidenceScore = confidence,
                                    Metadata = new Dictionary<string, string>
                                    {
                                        ["ProcessName"] = process.ProcessName,
                                        ["ProcessId"] = process.Id.ToString(),
                                        ["Signature"] = foundSignature,
                                        ["Confidence"] = confidence.ToString("F2")
                                    }
                                });
                            }
                        }
                    }
                    catch
                    {
                        // Ignore access denied errors
                    }
                    finally
                    {
                        process.Dispose();
                    }
                }

                return results;
            });
        }

        private bool IsMemoryScannerProcess(Process process)
        {
            try
            {
                string processName = process.ProcessName.ToLowerInvariant();
                string windowTitle = GetMainWindowTitle(process).ToLowerInvariant();

                return _suspiciousWindowTitles.Any(title =>
                    processName.Contains(title) || windowTitle.Contains(title));
            }
            catch
            {
                return false;
            }
        }

        private static bool IsSuspiciousForMemoryScan(Process process)
        {
            try
            {
                string processName = process.ProcessName.ToLowerInvariant();

                string[] skipProcesses =
                [
                    "system", "svchost", "csrss", "wininit", "services",
                    "lsass", "explorer", "dwm", "conhost", "sihost",
                    "utorrent", "bittorrent", "qbittorrent",
                    "chrome", "firefox", "edge", "brave",
                    "steam", "epicgameslauncher", "origin",
                    "discord", "spotify", "teamspeak"
                ];

                if (skipProcesses.Any(sp => processName.Contains(sp)))
                    return false;

                return process.Threads.Count > 5 ||
                       process.WorkingSet64 > 50 * 1024 * 1024 ||
                       !string.IsNullOrEmpty(process.MainWindowTitle);
            }
            catch
            {
                return false;
            }
        }

        private bool ScanProcessMemoryForSignatures(Process process, out string foundSignature, out double confidence)
        {
            foundSignature = string.Empty;
            confidence = 0.0;

            try
            {
                IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process.Id);
                if (hProcess == IntPtr.Zero)
                    return false;

                try
                {
                    IntPtr address = IntPtr.Zero;
                    MEMORY_BASIC_INFORMATION memInfo;
                    int scannedRegions = 0;
                    const int maxRegionsToScan = 50;

                    while (VirtualQueryEx(hProcess, address, out memInfo, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) != 0
                           && scannedRegions < maxRegionsToScan)
                    {
                        if (memInfo.State == MEM_COMMIT &&
                            (memInfo.Protect == PAGE_READWRITE || memInfo.Protect == PAGE_EXECUTE_READWRITE))
                        {
                            int regionSize = Math.Min((int)memInfo.RegionSize, 512 * 1024);
                            byte[] buffer = new byte[regionSize];

                            if (ReadProcessMemory(hProcess, memInfo.BaseAddress, buffer, regionSize, out int bytesRead))
                            {
                                foreach (var signatureEntry in _cheatSignatures)
                                {
                                    if (SearchPattern(buffer, signatureEntry.Value))
                                    {
                                        foundSignature = signatureEntry.Key;

                                        confidence = signatureEntry.Key.Contains("String") ? 0.99 : 0.75;

                                        return true;
                                    }
                                }
                            }
                        }

                        address = IntPtr.Add(memInfo.BaseAddress, (int)memInfo.RegionSize);
                        scannedRegions++;
                    }
                }
                finally
                {
                    CloseHandle(hProcess);
                }
            }
            catch
            {
                // Ignore errors
            }

            return false;
        }

        private static bool SearchPattern(byte[] data, byte[] pattern)
        {
            if (pattern.Length > data.Length)
                return false;

            int patternLength = pattern.Length;
            int dataLength = data.Length - patternLength;

            for (int i = 0; i < dataLength; i++)
            {
                bool found = true;
                for (int j = 0; j < patternLength; j++)
                {
                    if (pattern[j] != 0x00 && data[i + j] != pattern[j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found)
                    return true;
            }

            return false;
        }

        private static ThreatLevel DetermineThreatLevel(double confidence)
        {
            return confidence switch
            {
                >= 0.9 => ThreatLevel.Critical,
                >= 0.75 => ThreatLevel.High,
                >= 0.5 => ThreatLevel.Medium,
                _ => ThreatLevel.Low
            };
        }

        private static string GetMainWindowTitle(Process process)
        {
            try
            {
                return process.MainWindowTitle;
            }
            catch
            {
                return string.Empty;
            }
        }
    }
}