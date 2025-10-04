using SentinelAC.Core.Interfaces;

namespace SentinelAC.Core.Data
{
    public sealed class SignatureDatabase : ISignatureDatabase
    {
        private HashSet<string> _knownThreats;
        private HashSet<string> _suspiciousPatterns;
        private readonly string _databasePath;

        public SignatureDatabase(string databasePath = "signatures.db")
        {
            _databasePath = databasePath;
            _knownThreats = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _suspiciousPatterns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            LoadSignatures();
        }

        public bool IsKnownThreat(string name)
        {
            return _knownThreats.Contains(name);
        }

        public bool IsSuspiciousPattern(string name)
        {
            string lowerName = name.ToLowerInvariant();
            return _suspiciousPatterns.Any(pattern => lowerName.Contains(pattern));
        }

        public void LoadSignatures()
        {
            LoadDefaultSignatures();

            if (File.Exists(_databasePath))
            {
                LoadFromFile();
            }
        }

        public void UpdateSignatures()
        {
            SaveToFile();
        }

        private void LoadDefaultSignatures()
        {
            _knownThreats = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "cheatengine", "cheatengine-x86_64", "cheatengine-i386",
                "x64dbg", "x32dbg", "ollydbg", "ida", "ida64",
                "processhacker", "extremeinjector", "winject",
                "reshade", "rivatuner", "msi afterburner",
                "artmoney", "gameguardian", "lucky patcher"
            };

            _suspiciousPatterns = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "cheat", "hack", "trainer", "injector", "inject",
                "bypass", "unlocker", "crack", "keygen",
                "aimbot", "wallhack", "esp", "triggerbot",
                "macro", "autoclicker", "mouserecorder",
                "debugger", "disassembler", "decompiler"
            };
        }

        private void LoadFromFile()
        {
            string[] lines = File.ReadAllLines(_databasePath);
            foreach (string line in lines)
            {
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                    continue;

                if (line.StartsWith("THREAT:"))
                {
                    _knownThreats.Add(line.Substring(7).Trim());
                }
                else if (line.StartsWith("PATTERN:"))
                {
                    _suspiciousPatterns.Add(line.Substring(8).Trim());
                }
            }
        }

        private void SaveToFile()
        {
            List<string> lines = ["# SentinelAC Signature Database", "# Format: THREAT:name or PATTERN:pattern", ""];

            foreach (string threat in _knownThreats)
            {
                lines.Add($"THREAT:{threat}");
            }

            lines.Add("");

            foreach (string pattern in _suspiciousPatterns)
            {
                lines.Add($"PATTERN:{pattern}");
            }

            File.WriteAllLines(_databasePath, lines);
        }
    }
}