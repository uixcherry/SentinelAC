using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using SentinelAC.Core.Interfaces;
using SentinelAC.Core.Models;

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

        private readonly byte[][] _cheatEngineSignatures =
        [
            // Cheat Engine signatures
            Encoding.ASCII.GetBytes("Cheat Engine"),
            Encoding.ASCII.GetBytes("CESERVER"),
            Encoding.ASCII.GetBytes("speedhack"),
            new byte[] { 0x8B, 0x45, 0xFC, 0x50, 0xFF, 0x15 }, // Common CE pattern
            new byte[] { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x0C } // CE function prologue
        ];

        private readonly string[] _suspiciousWindowTitles =
        [
            "cheat engine", "memory editor", "artmoney", "game hacker",
            "memory scanner", "process hacker", "memory viewer"
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
                                Metadata = new Dictionary<string, string>
                                {
                                    ["ProcessName"] = process.ProcessName,
                                    ["ProcessId"] = process.Id.ToString(),
                                    ["WindowTitle"] = GetMainWindowTitle(process)
                                }
                            });
                        }

                        if (ScanProcessMemoryForSignatures(process, out string foundSignature))
                        {
                            results.Add(new DetectionResult
                            {
                                Type = DetectionType.MemoryScanner,
                                Level = ThreatLevel.High,
                                Description = $"Cheat signature found in memory: {process.ProcessName}",
                                Details = $"Process ID: {process.Id}, Signature: {foundSignature}",
                                Metadata = new Dictionary<string, string>
                                {
                                    ["ProcessName"] = process.ProcessName,
                                    ["ProcessId"] = process.Id.ToString(),
                                    ["Signature"] = foundSignature
                                }
                            });
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

        private bool ScanProcessMemoryForSignatures(Process process, out string foundSignature)
        {
            foundSignature = string.Empty;

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
                    const int maxRegionsToScan = 100; // Limit for performance

                    while (VirtualQueryEx(hProcess, address, out memInfo, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) != 0
                           && scannedRegions < maxRegionsToScan)
                    {
                        if (memInfo.State == MEM_COMMIT &&
                            (memInfo.Protect == PAGE_READWRITE || memInfo.Protect == PAGE_EXECUTE_READWRITE))
                        {
                            int regionSize = Math.Min((int)memInfo.RegionSize, 1024 * 1024); // Max 1MB per region
                            byte[] buffer = new byte[regionSize];

                            if (ReadProcessMemory(hProcess, memInfo.BaseAddress, buffer, regionSize, out int bytesRead))
                            {
                                foreach (var signature in _cheatEngineSignatures)
                                {
                                    if (SearchPattern(buffer, signature))
                                    {
                                        foundSignature = BitConverter.ToString(signature).Replace("-", " ");
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
            }

            return false;
        }

        private static bool SearchPattern(byte[] data, byte[] pattern)
        {
            int patternLength = pattern.Length;
            int dataLength = data.Length - patternLength;

            for (int i = 0; i < dataLength; i++)
            {
                bool found = true;
                for (int j = 0; j < patternLength; j++)
                {
                    if (data[i + j] != pattern[j])
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