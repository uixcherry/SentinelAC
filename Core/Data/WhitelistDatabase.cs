namespace SentinelAC.Core.Data
{
    public sealed class WhitelistDatabase
    {
        private readonly HashSet<string> _trustedProcesses;
        private readonly HashSet<string> _trustedModules;
        private readonly HashSet<string> _trustedPaths;
        private readonly HashSet<string> _trustedServices;

        public WhitelistDatabase()
        {
            _trustedProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "devenv", "msbuild", "servicehub", "vbcscompiler",
                "testhost", "vstest.console", "dotnet", "conhost",
                "explorer", "svchost", "dwm", "csrss", "wininit",
                "services", "lsass", "winlogon", "fontdrvhost"
            };

            _trustedModules = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "microsoft.visualstudio", "system.windows", "presentationframework",
                "presentationcore", "windowsbase", "system.xaml", "wpfgfx",
                "system.configuration.configurationmanager", "uiautomation",
                "icsharpcode.decompiler", "microsoft.extensions.dependencyinjection",
                "debuggerproxy", "directwriteforwarder", "d3dcompiler",
                "vcruntime140", "msvcp140", "ucrtbase"
            };

            _trustedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                @"c:\windows\system32",
                @"c:\windows\syswow64",
                @"c:\program files\microsoft visual studio",
                @"c:\program files\dotnet",
                @"c:\program files\windowsapps",
                @"c:\windows\microsoft.net",
                @"c:\windows\assembly"
            };

            _trustedServices = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "easyanticheat", "easyanticheat_eos", "battleye", "vgc", "vgk", "faceit",
                "anticheatexpert", "anticheatexpert protection", "anticheatexpert service",
                "fdrespub", "fdphost", "wcncsvc", "bthserv",
                "vanguard", "riot vanguard", "punkbuster", "xigncode", "gameguard",
                "nprotect", "hackshield", "xtrap", "wellbia"
            };
        }

        public bool IsTrustedProcess(string processName)
        {
            return _trustedProcesses.Any(tp => processName.Contains(tp));
        }

        public bool IsTrustedModule(string moduleName)
        {
            return _trustedModules.Any(tm => moduleName.Contains(tm));
        }

        public bool IsTrustedPath(string path)
        {
            string lowerPath = path.ToLowerInvariant();
            return _trustedPaths.Any(tp => lowerPath.StartsWith(tp));
        }

        public bool IsTrustedService(string serviceName)
        {
            string lowerName = serviceName.ToLowerInvariant();
            return _trustedServices.Any(ts => lowerName.Equals(ts) || lowerName.Contains(ts));
        }
    }
}