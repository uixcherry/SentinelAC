using SentinelAC.Core.Interfaces;
using SentinelAC.Core.Models;
using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace SentinelAC.Detectors
{
    [SupportedOSPlatform("windows")]
    public sealed class VirtualizationDetector : IDetector
    {
        [DllImport("kernel32.dll")]
        private static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_INFO
        {
            public ushort processorArchitecture;
            readonly ushort reserved;
            public uint pageSize;
            public IntPtr minimumApplicationAddress;
            public IntPtr maximumApplicationAddress;
            public IntPtr activeProcessorMask;
            public uint numberOfProcessors;
            public uint processorType;
            public uint allocationGranularity;
            public ushort processorLevel;
            public ushort processorRevision;
        }

        public DetectionType Type => DetectionType.Virtualization;
        public bool RequiresAdminRights => false;

        public async Task<List<DetectionResult>> ScanAsync()
        {
            return await Task.Run(() =>
            {
                List<DetectionResult> results = [];

                DetectionResult? vmResult = CheckForVirtualMachine();
                if (vmResult != null)
                {
                    results.Add(vmResult);
                }

                DetectionResult? hwResult = CheckHardwareCharacteristics();
                if (hwResult != null)
                {
                    results.Add(hwResult);
                }

                return results;
            });
        }

        private static DetectionResult? CheckForVirtualMachine()
        {
            try
            {
                using (ManagementObjectSearcher searcher = new("SELECT * FROM Win32_ComputerSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string manufacturer = obj["Manufacturer"]?.ToString()?.ToLowerInvariant() ?? string.Empty;
                        string model = obj["Model"]?.ToString()?.ToLowerInvariant() ?? string.Empty;

                        if (manufacturer.Contains("vmware") || manufacturer.Contains("virtual") ||
                            model.Contains("vmware") || model.Contains("virtualbox") ||
                            model.Contains("virtual machine") || model.Contains("qemu"))
                        {
                            return new DetectionResult
                            {
                                Type = DetectionType.Virtualization,
                                Level = ThreatLevel.High,
                                Description = "Virtual Machine detected",
                                Details = $"Manufacturer: {manufacturer}, Model: {model}",
                                Metadata = new Dictionary<string, string>
                                {
                                    ["Manufacturer"] = manufacturer,
                                    ["Model"] = model
                                }
                            };
                        }
                    }
                }

                using (ManagementObjectSearcher searcher = new("SELECT * FROM Win32_BIOS"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string serialNumber = obj["SerialNumber"]?.ToString()?.ToLowerInvariant() ?? string.Empty;
                        string version = obj["Version"]?.ToString()?.ToLowerInvariant() ?? string.Empty;

                        if (serialNumber.Contains("vmware") || version.Contains("vbox") || version.Contains("qemu"))
                        {
                            return new DetectionResult
                            {
                                Type = DetectionType.Virtualization,
                                Level = ThreatLevel.High,
                                Description = "Virtual Machine BIOS detected",
                                Details = $"BIOS Version: {version}, Serial: {serialNumber}",
                                Metadata = new Dictionary<string, string>
                                {
                                    ["BIOSVersion"] = version,
                                    ["SerialNumber"] = serialNumber
                                }
                            };
                        }
                    }
                }
            }
            catch
            {
            }

            return null;
        }

        private static DetectionResult? CheckHardwareCharacteristics()
        {
            try
            {
                GetSystemInfo(out SYSTEM_INFO sysInfo);

                if (sysInfo.numberOfProcessors <= 2)
                {
                    return new DetectionResult
                    {
                        Type = DetectionType.Virtualization,
                        Level = ThreatLevel.Medium,
                        Description = "Suspicious hardware configuration",
                        Details = $"Low CPU count detected: {sysInfo.numberOfProcessors} processors",
                        Metadata = new Dictionary<string, string>
                        {
                            ["ProcessorCount"] = sysInfo.numberOfProcessors.ToString()
                        }
                    };
                }
            }
            catch
            {
            }

            return null;
        }
    }
}