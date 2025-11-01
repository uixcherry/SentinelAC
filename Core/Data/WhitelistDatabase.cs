using System.Text.RegularExpressions;

namespace SentinelAC.Core.Data
{
    public sealed class WhitelistDatabase
    {
        private readonly HashSet<string> _trustedProcesses;
        private readonly HashSet<string> _trustedModules;
        private readonly HashSet<string> _trustedPaths;
        private readonly HashSet<string> _trustedServices;
        private readonly List<Regex> _trustedPathPatterns;
        private readonly string _whitelistConfigPath;

        public WhitelistDatabase(string configPath = "whitelist.cfg")
        {
            _whitelistConfigPath = configPath;
            _trustedPathPatterns = new List<Regex>();

            _trustedProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "devenv", "msbuild", "servicehub", "vbcscompiler",
                "testhost", "vstest.console", "dotnet", "conhost",
                "rider64", "rider", "jetbrains", "resharper",
                "code", "vscode", "atom", "sublime",

                "explorer", "svchost", "dwm", "csrss", "wininit",
                "services", "lsass", "winlogon", "fontdrvhost",
                "smss", "wininit", "taskhostw", "runtimebroker",
                "sihost", "ctfmon", "searchindexer", "searchapp",
                "startmenuexperiencehost", "shellexperiencehost",
                "applicationframehost", "systemsettings", "lockapp",

                "roslyn", "csc", "vbc", "fsc", "csi",

                "steam", "epicgameslauncher", "origin", "uplay",
                "battlenet", "gog", "discord", "teamspeak",
                "playnite", "launchbox", "retroarch",

                "taskmgr", "regedit", "cmd", "powershell",
                "notepad", "mmc", "perfmon", "eventvwr",

                "mdnsresponder", "bonjour", "bonjourservice",
                "applemobiledeviceservice", "itunes", "icloud",

                "bluestacks", "bluestacksservices", "noxplayer",
                "ldplayer", "memu", "gameloop",

                "nvidia share", "nvidia overlay", "nvcontainer",
                "nvspcaps64", "shadowplay", "geforcenow",
                "amd radeon", "radeonSettings", "amddvr",

                "discord", "discordcanary", "spotify", "telegram",
                "slack", "zoom", "skype", "teams",

                "chrome", "firefox", "edge", "brave", "opera",
                "vivaldi", "yandex", "chromium",

                "obs64", "obs32", "xsplit", "streamlabs",

                "sentinelac", "sentinelac.exe"
            };

            _trustedModules = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "microsoft.visualstudio", "system.windows", "presentationframework",
                "presentationcore", "windowsbase", "system.xaml", "wpfgfx",
                "system.configuration.configurationmanager", "uiautomation",
                "icsharpcode.decompiler", "microsoft.extensions",
                "debuggerproxy", "directwriteforwarder", "d3dcompiler",

                "illink.roslynanalyzer", "roslyn", "microsoft.codeanalysis",
                "codeanalysis", "analyzer",

                "vcruntime140", "msvcp140", "ucrtbase", "msvcr",
                "kernel32", "ntdll", "user32", "gdi32", "advapi32",
                "ole32", "shell32", "comctl32", "comdlg32",
                "ws2_32", "winhttp", "wininet", "crypt32",

                "d3d9", "d3d10", "d3d11", "d3d12", "dxgi",
                "opengl32", "vulkan", "nvapi", "amdags",
                "atiadlxx", "nvfbc", "nvifr", "nvencodeapi",

                "easyanticheat", "battleye", "vanguard", "faceit",
                "ricochet", "anticheatexpert", "xigncode", "gameguard",

                "discord_voice", "discord_game_sdk", "steam_api",
                "galaxy", "epiconlineservices", "eos_sdk",

                "bonjour", "mdnsresponder", "dns-sd",

                "bluestack", "nox", "ldplayer",

                "nvda", "nvenc", "nvcuda", "nvcuvid",
                "amdocl", "amdxc", "amdhip",

                "obs", "obs-ffmpeg", "obs-plugins",
                "xsplit", "streamlabs"
            };

            _trustedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                @"c:\windows\system32",
                @"c:\windows\syswow64",
                @"c:\windows\winsxs",
                @"c:\windows\assembly",
                @"c:\windows\microsoft.net",

                @"c:\program files\microsoft visual studio",
                @"c:\program files\dotnet",
                @"c:\program files\windowsapps",
                @"c:\program files\windows defender",
                @"c:\program files\common files\microsoft shared",
                @"c:\program files (x86)\microsoft visual studio",
                @"c:\program files (x86)\windows kits",

                @"c:\program files\jetbrains",
                @"c:\program files\microsoft sdks",
                @"c:\program files\git",

                @"c:\program files (x86)\steam",
                @"c:\program files\steam",
                @"c:\program files\epic games",
                @"c:\program files (x86)\origin",
                @"c:\program files\ubisoft",
                @"c:\program files (x86)\battle.net",
                @"c:\program files\gog galaxy",

                @"c:\program files\easyanticheat",
                @"c:\program files\common files\battleye",
                @"c:\program files\riot vanguard",

                @"c:\program files\dotnet\shared",
                @"c:\users\.nuget\packages",

                @"c:\program files\bonjour",
                @"c:\program files (x86)\bonjour",
                @"c:\program files\common files\apple",

                @"c:\program files\bluestacks",
                @"c:\program files (x86)\bluestacks",
                @"c:\program files\noxplayer",
                @"c:\program files (x86)\noxplayer",

                @"c:\program files\nvidia corporation",
                @"c:\program files (x86)\nvidia corporation",
                @"c:\windows\system32\driverstore\filerepository",

                @"c:\program files\amd",
                @"c:\program files\amd\cim",

                @"c:\program files\discord",
                @"c:\program files (x86)\discord",
                @"c:\program files\obs-studio",
                @"c:\program files (x86)\obs-studio"
            };

            _trustedServices = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "easyanticheat", "easyanticheat_eos", "battleye", "vgc", "vgk",
                "faceit", "anticheatexpert", "anticheatexpert protection",
                "anticheatexpert service", "vanguard", "riot vanguard",
                "punkbuster", "xigncode", "gameguard", "nprotect",
                "hackshield", "xtrap", "wellbia",

                "fdrespub", "fdphost", "wcncsvc", "bthserv",
                "wuauserv", "bits", "cryptsvc", "trustedinstaller",
                "mpssvc", "wscsvc", "windefend", "securityhealthservice",

                "mssqlserver", "sqlwriter", "docker", "vmware",

                "bonjour service", "bonjourservice", "mdnsresponder",
                "apple mobile device service",

                "bluestacks hypervisor", "bluestacks service",
                "bsthdandroidsvc", "bsthdlogrotatorservice",

                "nvdisplay.containerlocalsystem", "nvcontainer",
                "nvspcapsvc", "nvidia telemetry container",

                "amdrsserv", "amddvr"
            };

            InitializeTrustedPathPatterns();
            LoadWhitelistConfig();
        }

        private void InitializeTrustedPathPatterns()
        {
            string[] patterns =
            [
                @"^c:\\users\\[^\\]+\\appdata\\local\\temp\\roslyn\\.*",
                @"^c:\\users\\[^\\]+\\appdata\\local\\microsoft\\visualstudio\\.*",
                @"^c:\\users\\[^\\]+\\.nuget\\packages\\.*",
                @"^c:\\users\\[^\\]+\\.vscode\\extensions\\.*",
                @"^c:\\program files\\dotnet\\.*",
                @"^c:\\windows\\assembly\\.*",
                @"^c:\\windows\\microsoft\.net\\.*",
                @"^c:\\program files\\nvidia corporation\\.*",
                @"^c:\\program files \(x86\)\\nvidia corporation\\.*",
                @"^c:\\windows\\system32\\driverstore\\filerepository\\.*",
                @"^c:\\program files\\bonjour\\.*",
                @"^c:\\program files \(x86\)\\bonjour\\.*",
                @"^c:\\program files\\bluestacks.*",
                @"^c:\\programdata\\bluestacks.*",
                @"^c:\\users\\[^\\]+\\appdata\\local\\bluestacks.*",
                @"^c:\\users\\.*\\appdata\\local\\temp\\.*\.tmp\.node$"
            ];

            foreach (string pattern in patterns)
            {
                try
                {
                    _trustedPathPatterns.Add(new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled));
                }
                catch
                {
                }
            }
        }

        private void LoadWhitelistConfig()
        {
            if (!File.Exists(_whitelistConfigPath))
                return;

            try
            {
                string[] lines = File.ReadAllLines(_whitelistConfigPath);
                foreach (string line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                        continue;

                    string[] parts = line.Split(':', 2);
                    if (parts.Length != 2)
                        continue;

                    string type = parts[0].Trim().ToLowerInvariant();
                    string value = parts[1].Trim();

                    switch (type)
                    {
                        case "process":
                            _trustedProcesses.Add(value);
                            break;
                        case "module":
                            _trustedModules.Add(value);
                            break;
                        case "path":
                            _trustedPaths.Add(value);
                            break;
                        case "service":
                            _trustedServices.Add(value);
                            break;
                        case "pattern":
                            try
                            {
                                _trustedPathPatterns.Add(new Regex(value, RegexOptions.IgnoreCase | RegexOptions.Compiled));
                            }
                            catch
                            {
                            }
                            break;
                    }
                }
            }
            catch
            {
            }
        }

        public bool IsTrustedProcess(string processName)
        {
            if (string.IsNullOrEmpty(processName))
                return false;

            string lower = processName.ToLowerInvariant();
            return _trustedProcesses.Any(tp => lower.Contains(tp));
        }

        public bool IsTrustedModule(string moduleName)
        {
            if (string.IsNullOrEmpty(moduleName))
                return false;

            string lower = moduleName.ToLowerInvariant();
            return _trustedModules.Any(tm => lower.Contains(tm));
        }

        public bool IsTrustedPath(string path)
        {
            if (string.IsNullOrEmpty(path))
                return false;

            string lowerPath = path.ToLowerInvariant();

            if (_trustedPaths.Any(tp => lowerPath.StartsWith(tp)))
                return true;

            foreach (Regex pattern in _trustedPathPatterns)
            {
                if (pattern.IsMatch(lowerPath))
                    return true;
            }

            return false;
        }

        public bool IsTrustedService(string serviceName)
        {
            if (string.IsNullOrEmpty(serviceName))
                return false;

            string lowerName = serviceName.ToLowerInvariant();
            return _trustedServices.Any(ts => lowerName.Equals(ts, StringComparison.OrdinalIgnoreCase) ||
                                              lowerName.Contains(ts));
        }

        public void AddTrustedProcess(string processName)
        {
            if (!string.IsNullOrEmpty(processName))
                _trustedProcesses.Add(processName);
        }

        public void AddTrustedModule(string moduleName)
        {
            if (!string.IsNullOrEmpty(moduleName))
                _trustedModules.Add(moduleName);
        }

        public void AddTrustedPath(string path)
        {
            if (!string.IsNullOrEmpty(path))
                _trustedPaths.Add(path);
        }

        public void AddTrustedService(string serviceName)
        {
            if (!string.IsNullOrEmpty(serviceName))
                _trustedServices.Add(serviceName);
        }

        public void SaveWhitelistConfig()
        {
            try
            {
                List<string> lines =
                [
                    "# SentinelAC Whitelist Configuration",
                    "# Format: <type>:<value>",
                    "# Types: process, module, path, service, pattern",
                    ""
                ];

                lines.Add("# Processes");
                foreach (string process in _trustedProcesses.OrderBy(p => p))
                {
                    lines.Add($"process:{process}");
                }

                lines.Add("");
                lines.Add("# Modules");
                foreach (string module in _trustedModules.OrderBy(m => m))
                {
                    lines.Add($"module:{module}");
                }

                lines.Add("");
                lines.Add("# Paths");
                foreach (string path in _trustedPaths.OrderBy(p => p))
                {
                    lines.Add($"path:{path}");
                }

                lines.Add("");
                lines.Add("# Services");
                foreach (string service in _trustedServices.OrderBy(s => s))
                {
                    lines.Add($"service:{service}");
                }

                File.WriteAllLines(_whitelistConfigPath, lines);
            }
            catch
            {
            }
        }

        public int GetTrustedProcessCount() => _trustedProcesses.Count;
        public int GetTrustedModuleCount() => _trustedModules.Count;
        public int GetTrustedPathCount() => _trustedPaths.Count;
        public int GetTrustedServiceCount() => _trustedServices.Count;
    }
}