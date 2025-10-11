using SentinelAC.Core.Interfaces;
using SentinelAC.Core.Models;
using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace SentinelAC.Detectors
{
    [SupportedOSPlatform("windows")]
    public sealed class FileSystemDetector : IDetector
    {
        private readonly ISignatureDatabase _signatureDatabase;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr FindFirstStreamW(string lpFileName, uint InfoLevel, out WIN32_FIND_STREAM_DATA lpFindStreamData, uint dwFlags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool FindNextStreamW(IntPtr hFindStream, out WIN32_FIND_STREAM_DATA lpFindStreamData);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FindClose(IntPtr hFindFile);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WIN32_FIND_STREAM_DATA
        {
            public long StreamSize;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
            public string cStreamName;
        }

        private const uint FIND_FIRST_EX_CASE_SENSITIVE = 1;
        private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

        public DetectionType Type => DetectionType.FileIntegrity;
        public bool RequiresAdminRights => false;

        public FileSystemDetector(ISignatureDatabase signatureDatabase)
        {
            _signatureDatabase = signatureDatabase;
        }

        public async Task<List<DetectionResult>> ScanAsync()
        {
            return await Task.Run(() =>
            {
                List<DetectionResult> results = [];

                CheckUSBDevices(results);
                CheckHiddenFiles(results);
                CheckAlternateDataStreams(results);
                CheckRecentlyModifiedExecutables(results);
                CheckSuspiciousFileLocations(results);

                return results;
            });
        }

        private static void CheckUSBDevices(List<DetectionResult> results)
        {
            try
            {
                using ManagementObjectSearcher searcher = new("SELECT * FROM Win32_DiskDrive WHERE InterfaceType='USB'");
                ManagementObjectCollection drives = searcher.Get();

                foreach (ManagementObject drive in drives)
                {
                    string deviceId = drive["DeviceID"]?.ToString() ?? string.Empty;
                    string model = drive["Model"]?.ToString() ?? string.Empty;
                    string serialNumber = drive["SerialNumber"]?.ToString() ?? string.Empty;
                    ulong size = drive["Size"] != null ? Convert.ToUInt64(drive["Size"]) : 0;

                    using ManagementObjectSearcher partitionSearcher = new($"ASSOCIATORS OF {{Win32_DiskDrive.DeviceID='{deviceId}'}} WHERE AssocClass=Win32_DiskDriveToDiskPartition");
                    foreach (ManagementObject partition in partitionSearcher.Get())
                    {
                        using ManagementObjectSearcher logicalSearcher = new($"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{partition["DeviceID"]}'}} WHERE AssocClass=Win32_LogicalDiskToPartition");
                        foreach (ManagementObject logical in logicalSearcher.Get())
                        {
                            string driveLetter = logical["DeviceID"]?.ToString() ?? string.Empty;

                            if (!string.IsNullOrEmpty(driveLetter) && Directory.Exists(driveLetter))
                            {
                                List<DetectionResult> usbResults = ScanUSBDrive(driveLetter, model, serialNumber);
                                results.AddRange(usbResults);
                            }
                        }
                    }

                    results.Add(new DetectionResult
                    {
                        Type = DetectionType.FileIntegrity,
                        Level = ThreatLevel.None,
                        Description = $"USB device detected: {model}",
                        Details = $"Serial: {serialNumber}, Size: {size / (1024 * 1024 * 1024)}GB",
                        Metadata = new Dictionary<string, string>
                        {
                            ["DeviceID"] = deviceId,
                            ["Model"] = model,
                            ["SerialNumber"] = serialNumber,
                            ["Size"] = size.ToString()
                        }
                    });
                }
            }
            catch
            {
            }
        }

        private static List<DetectionResult> ScanUSBDrive(string driveLetter, string deviceModel, string serialNumber)
        {
            List<DetectionResult> results = [];

            try
            {
                string[] executableExtensions = [".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".scr"];
                DirectoryInfo driveInfo = new(driveLetter);

                FileInfo[] files = driveInfo.GetFiles("*.*", SearchOption.AllDirectories);

                foreach (FileInfo file in files)
                {
                    try
                    {
                        string extension = file.Extension.ToLowerInvariant();

                        if (executableExtensions.Contains(extension))
                        {
                            if ((file.Attributes & FileAttributes.Hidden) == FileAttributes.Hidden)
                            {
                                results.Add(new DetectionResult
                                {
                                    Type = DetectionType.FileIntegrity,
                                    Level = ThreatLevel.High,
                                    Description = $"Hidden executable found on USB: {file.Name}",
                                    Details = $"Device: {deviceModel}, Path: {file.FullName}",
                                    Metadata = new Dictionary<string, string>
                                    {
                                        ["FileName"] = file.Name,
                                        ["FilePath"] = file.FullName,
                                        ["FileSize"] = file.Length.ToString(),
                                        ["DeviceModel"] = deviceModel,
                                        ["SerialNumber"] = serialNumber,
                                        ["FileHash"] = ComputeFileHash(file.FullName)
                                    }
                                });
                            }

                            if (file.Name.ToLowerInvariant().Contains("autorun"))
                            {
                                results.Add(new DetectionResult
                                {
                                    Type = DetectionType.FileIntegrity,
                                    Level = ThreatLevel.Critical,
                                    Description = $"Autorun file detected on USB: {file.Name}",
                                    Details = $"Device: {deviceModel}, Path: {file.FullName}",
                                    Metadata = new Dictionary<string, string>
                                    {
                                        ["FileName"] = file.Name,
                                        ["FilePath"] = file.FullName,
                                        ["DeviceModel"] = deviceModel,
                                        ["SerialNumber"] = serialNumber
                                    }
                                });
                            }
                        }
                    }
                    catch
                    {
                    }
                }
            }
            catch
            {
            }

            return results;
        }

        private void CheckHiddenFiles(List<DetectionResult> results)
        {
            string[] criticalPaths =
            [
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)
            ];

            foreach (string path in criticalPaths)
            {
                try
                {
                    DirectoryInfo dirInfo = new(path);
                    FileInfo[] hiddenFiles = dirInfo.GetFiles("*.*", SearchOption.TopDirectoryOnly)
                        .Where(f => (f.Attributes & FileAttributes.Hidden) == FileAttributes.Hidden)
                        .ToArray();

                    foreach (FileInfo file in hiddenFiles)
                    {
                        try
                        {
                            string fileName = file.Name.ToLowerInvariant();

                            if (_signatureDatabase.IsSuspiciousPattern(fileName))
                            {
                                results.Add(new DetectionResult
                                {
                                    Type = DetectionType.FileIntegrity,
                                    Level = ThreatLevel.High,
                                    Description = $"Suspicious hidden file: {file.Name}",
                                    Details = $"Path: {file.FullName}, Size: {file.Length} bytes",
                                    Metadata = new Dictionary<string, string>
                                    {
                                        ["FileName"] = file.Name,
                                        ["FilePath"] = file.FullName,
                                        ["FileSize"] = file.Length.ToString(),
                                        ["Created"] = file.CreationTime.ToString("yyyy-MM-dd HH:mm:ss"),
                                        ["Modified"] = file.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                                    }
                                });
                            }
                        }
                        catch
                        {
                        }
                    }
                }
                catch
                {
                }
            }
        }

        private static void CheckAlternateDataStreams(List<DetectionResult> results)
        {
            string[] pathsToCheck =
            [
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
            ];

            foreach (string basePath in pathsToCheck)
            {
                try
                {
                    DirectoryInfo dirInfo = new(basePath);
                    FileInfo[] files = dirInfo.GetFiles("*.*", SearchOption.TopDirectoryOnly);

                    foreach (FileInfo file in files.Take(100))
                    {
                        try
                        {
                            List<string> streams = FindAlternateDataStreams(file.FullName);

                            if (streams.Count > 0)
                            {
                                results.Add(new DetectionResult
                                {
                                    Type = DetectionType.FileIntegrity,
                                    Level = ThreatLevel.Medium,
                                    Description = $"Alternate Data Stream detected: {file.Name}",
                                    Details = $"Path: {file.FullName}, Streams: {string.Join(", ", streams)}",
                                    Metadata = new Dictionary<string, string>
                                    {
                                        ["FileName"] = file.Name,
                                        ["FilePath"] = file.FullName,
                                        ["StreamCount"] = streams.Count.ToString(),
                                        ["Streams"] = string.Join(";", streams)
                                    }
                                });
                            }
                        }
                        catch
                        {
                        }
                    }
                }
                catch
                {
                }
            }
        }

        private static List<string> FindAlternateDataStreams(string filePath)
        {
            List<string> streams = [];

            try
            {
                WIN32_FIND_STREAM_DATA streamData;
                IntPtr hFind = FindFirstStreamW(filePath, 0, out streamData, 0);

                if (hFind != INVALID_HANDLE_VALUE)
                {
                    try
                    {
                        do
                        {
                            string streamName = streamData.cStreamName;
                            if (!string.IsNullOrEmpty(streamName) && !streamName.Equals("::$DATA", StringComparison.OrdinalIgnoreCase))
                            {
                                streams.Add(streamName);
                            }
                        }
                        while (FindNextStreamW(hFind, out streamData));
                    }
                    finally
                    {
                        FindClose(hFind);
                    }
                }
            }
            catch
            {
            }

            return streams;
        }

        private static void CheckRecentlyModifiedExecutables(List<DetectionResult> results)
        {
            string systemPath = Environment.GetFolderPath(Environment.SpecialFolder.System);
            DateTime cutoffDate = DateTime.Now.AddDays(-7);

            try
            {
                DirectoryInfo dirInfo = new(systemPath);
                FileInfo[] recentFiles = dirInfo.GetFiles("*.exe", SearchOption.TopDirectoryOnly)
                    .Where(f => f.LastWriteTime > cutoffDate)
                    .ToArray();

                foreach (FileInfo file in recentFiles)
                {
                    try
                    {
                        results.Add(new DetectionResult
                        {
                            Type = DetectionType.FileIntegrity,
                            Level = ThreatLevel.Medium,
                            Description = $"Recently modified system executable: {file.Name}",
                            Details = $"Path: {file.FullName}, Modified: {file.LastWriteTime}",
                            Metadata = new Dictionary<string, string>
                            {
                                ["FileName"] = file.Name,
                                ["FilePath"] = file.FullName,
                                ["FileSize"] = file.Length.ToString(),
                                ["Modified"] = file.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"),
                                ["FileHash"] = ComputeFileHash(file.FullName)
                            }
                        });
                    }
                    catch
                    {
                    }
                }
            }
            catch
            {
            }
        }

        private void CheckSuspiciousFileLocations(List<DetectionResult> results)
        {
            string[] suspiciousLocations =
            [
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
                Path.Combine(Environment.GetEnvironmentVariable("TEMP") ?? string.Empty),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop))
            ];

            string[] executableExtensions = [".exe", ".dll", ".sys", ".scr"];

            foreach (string location in suspiciousLocations.Where(Directory.Exists))
            {
                try
                {
                    DirectoryInfo dirInfo = new(location);
                    FileInfo[] files = dirInfo.GetFiles("*.*", SearchOption.TopDirectoryOnly)
                        .Where(f => executableExtensions.Contains(f.Extension.ToLowerInvariant()))
                        .ToArray();

                    foreach (FileInfo file in files)
                    {
                        try
                        {
                            string fileName = file.Name.ToLowerInvariant();

                            if (_signatureDatabase.IsKnownThreat(fileName) || _signatureDatabase.IsSuspiciousPattern(fileName))
                            {
                                results.Add(new DetectionResult
                                {
                                    Type = DetectionType.FileIntegrity,
                                    Level = ThreatLevel.High,
                                    Description = $"Suspicious executable in temporary location: {file.Name}",
                                    Details = $"Path: {file.FullName}, Size: {file.Length} bytes",
                                    Metadata = new Dictionary<string, string>
                                    {
                                        ["FileName"] = file.Name,
                                        ["FilePath"] = file.FullName,
                                        ["FileSize"] = file.Length.ToString(),
                                        ["Created"] = file.CreationTime.ToString("yyyy-MM-dd HH:mm:ss"),
                                        ["FileHash"] = ComputeFileHash(file.FullName)
                                    }
                                });
                            }
                        }
                        catch
                        {
                        }
                    }
                }
                catch
                {
                }
            }
        }

        private static string ComputeFileHash(string filePath)
        {
            try
            {
                using FileStream stream = File.OpenRead(filePath);
                byte[] hash = SHA256.HashData(stream);
                return Convert.ToHexString(hash);
            }
            catch
            {
                return "ERROR";
            }
        }
    }
}