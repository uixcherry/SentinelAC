using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using SentinelAC.Core.Interfaces;
using SentinelAC.Core.Models;

namespace SentinelAC.Detectors
{
    [SupportedOSPlatform("windows")]
    public sealed class FileIntegrityDetector : IDetector
    {
        private const uint TRUST_E_NOSIGNATURE = 0x800B0100;
        private const uint TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004;
        private const uint TRUST_E_PROVIDER_UNKNOWN = 0x800B0001;
        private const uint CERT_E_EXPIRED = 0x800B0101;

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
        private static extern uint WinVerifyTrust(IntPtr hwnd, IntPtr pgActionID, IntPtr pWVTData);

        private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);
        private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            public IntPtr pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        public DetectionType Type => DetectionType.FileIntegrity;
        public bool RequiresAdminRights => false;

        public async Task<List<DetectionResult>> ScanAsync()
        {
            return await Task.Run(() =>
            {
                List<DetectionResult> results = [];

                string systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string[] criticalFiles =
                [
                    Path.Combine(systemRoot, "kernel32.dll"),
                    Path.Combine(systemRoot, "ntdll.dll"),
                    Path.Combine(systemRoot, "user32.dll"),
                    Path.Combine(systemRoot, "advapi32.dll")
                ];

                foreach (string file in criticalFiles)
                {
                    if (File.Exists(file))
                    {
                        DetectionResult? result = CheckFileIntegrity(file);
                        if (result != null)
                        {
                            results.Add(result);
                        }
                    }
                }

                return results;
            });
        }

        private static DetectionResult? CheckFileIntegrity(string filePath)
        {
            try
            {
                FileInfo fileInfo = new(filePath);
                string fileName = Path.GetFileName(filePath);

                if (fileInfo.LastWriteTime > DateTime.Now.AddDays(-30))
                {
                    if (!VerifyFileSignature(filePath))
                    {
                        return new DetectionResult
                        {
                            Type = DetectionType.FileIntegrity,
                            Level = ThreatLevel.High,
                            Description = $"Critical system file modified without valid signature: {fileName}",
                            Details = $"Path: {filePath}, Modified: {fileInfo.LastWriteTime}",
                            Metadata = new Dictionary<string, string>
                            {
                                ["FileName"] = fileName,
                                ["FilePath"] = filePath,
                                ["LastModified"] = fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"),
                                ["SignatureStatus"] = "Invalid or Missing"
                            }
                        };
                    }
                }
            }
            catch
            {
            }

            return null;
        }

        private static bool VerifyFileSignature(string filePath)
        {
            IntPtr filePathPtr = IntPtr.Zero;
            IntPtr wvtDataPtr = IntPtr.Zero;
            IntPtr fileInfoPtr = IntPtr.Zero;
            IntPtr guidPtr = IntPtr.Zero;

            try
            {
                filePathPtr = Marshal.StringToCoTaskMemUni(filePath);

                WINTRUST_FILE_INFO fileInfo = new()
                {
                    cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)),
                    pcwszFilePath = filePathPtr,
                    hFile = IntPtr.Zero,
                    pgKnownSubject = IntPtr.Zero
                };

                fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf(fileInfo));
                Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

                WINTRUST_DATA wvtData = new()
                {
                    cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA)),
                    pPolicyCallbackData = IntPtr.Zero,
                    pSIPClientData = IntPtr.Zero,
                    dwUIChoice = 2,
                    fdwRevocationChecks = 0,
                    dwUnionChoice = 1,
                    pFile = fileInfoPtr,
                    dwStateAction = 0,
                    hWVTStateData = IntPtr.Zero,
                    pwszURLReference = IntPtr.Zero,
                    dwProvFlags = 0x00000080,
                    dwUIContext = 0,
                    pSignatureSettings = IntPtr.Zero
                };

                wvtDataPtr = Marshal.AllocHGlobal(Marshal.SizeOf(wvtData));
                Marshal.StructureToPtr(wvtData, wvtDataPtr, false);

                guidPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Guid)));
                Marshal.StructureToPtr(WINTRUST_ACTION_GENERIC_VERIFY_V2, guidPtr, false);

                uint result = WinVerifyTrust(INVALID_HANDLE_VALUE, guidPtr, wvtDataPtr);

                return result == 0;
            }
            catch
            {
                return false;
            }
            finally
            {
                if (filePathPtr != IntPtr.Zero)
                    Marshal.FreeCoTaskMem(filePathPtr);
                if (fileInfoPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(fileInfoPtr);
                if (wvtDataPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(wvtDataPtr);
                if (guidPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(guidPtr);
            }
        }
    }
}