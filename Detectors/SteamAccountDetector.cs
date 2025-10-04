using Microsoft.Win32;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using SentinelAC.Core.Interfaces;
using SentinelAC.Core.Models;

namespace SentinelAC.Detectors
{
    [SupportedOSPlatform("windows")]
    public sealed class SteamAccountDetector : IDetector
    {
        public DetectionType Type => DetectionType.SteamAccounts;
        public bool RequiresAdminRights => false;

        public async Task<List<DetectionResult>> ScanAsync()
        {
            return await Task.Run(() =>
            {
                List<DetectionResult> results = [];
                List<SteamAccountInfo> accounts = [];

                CollectSteamAccounts(accounts);

                if (accounts.Count > 0)
                {
                    string accountDetails = FormatAccountDetails(accounts);

                    results.Add(new DetectionResult
                    {
                        Type = DetectionType.SteamAccounts,
                        Level = ThreatLevel.None,
                        Description = $"Found {accounts.Count} Steam account(s) on this PC",
                        Details = accountDetails,
                        Metadata = BuildMetadata(accounts)
                    });
                }

                return results;
            });
        }

        private static void CollectSteamAccounts(List<SteamAccountInfo> accounts)
        {
            string steamPath = GetSteamInstallPath();
            if (string.IsNullOrEmpty(steamPath))
                return;

            Dictionary<string, SteamAccountInfo> accountMap = new();

            string configPath = Path.Combine(steamPath, "config", "loginusers.vdf");
            if (File.Exists(configPath))
            {
                ParseLoginUsersVDF(configPath, accountMap);
            }

            string userdataPath = Path.Combine(steamPath, "userdata");
            if (Directory.Exists(userdataPath))
            {
                ScanUserdataFolders(userdataPath, accountMap);
            }

            accounts.AddRange(accountMap.Values.OrderByDescending(a => a.LastLogin));
        }

        private static void ParseLoginUsersVDF(string path, Dictionary<string, SteamAccountInfo> accountMap)
        {
            try
            {
                string content = File.ReadAllText(path);
                MatchCollection steamIdMatches = Regex.Matches(content, @"""(\d{17})""");

                foreach (Match match in steamIdMatches)
                {
                    string steamId = match.Groups[1].Value;
                    if (!accountMap.ContainsKey(steamId))
                    {
                        accountMap[steamId] = new SteamAccountInfo { SteamId64 = steamId };
                    }

                    int startIndex = match.Index;
                    string section = content.Substring(startIndex, Math.Min(500, content.Length - startIndex));

                    Match nameMatch = Regex.Match(section, @"""AccountName""\s+""([^""]+)""");
                    if (nameMatch.Success)
                    {
                        accountMap[steamId].AccountName = nameMatch.Groups[1].Value;
                    }

                    Match personaMatch = Regex.Match(section, @"""PersonaName""\s+""([^""]+)""");
                    if (personaMatch.Success)
                    {
                        accountMap[steamId].PersonaName = personaMatch.Groups[1].Value;
                    }

                    Match timestampMatch = Regex.Match(section, @"""Timestamp""\s+""(\d+)""");
                    if (timestampMatch.Success && long.TryParse(timestampMatch.Groups[1].Value, out long timestamp))
                    {
                        accountMap[steamId].LastLogin = DateTimeOffset.FromUnixTimeSeconds(timestamp).DateTime;
                    }
                }
            }
            catch
            {
            }
        }

        private static void ScanUserdataFolders(string userdataPath, Dictionary<string, SteamAccountInfo> accountMap)
        {
            try
            {
                string[] userFolders = Directory.GetDirectories(userdataPath);
                foreach (string folder in userFolders)
                {
                    string folderName = Path.GetFileName(folder);
                    if (long.TryParse(folderName, out long steamId3) && steamId3 > 0)
                    {
                        string steamId64 = ConvertSteamId3To64(steamId3);

                        if (!accountMap.ContainsKey(steamId64))
                        {
                            accountMap[steamId64] = new SteamAccountInfo { SteamId64 = steamId64 };
                        }

                        try
                        {
                            DirectoryInfo dirInfo = new(folder);
                            accountMap[steamId64].LastActivity = dirInfo.LastWriteTime;
                        }
                        catch
                        {
                        }
                    }
                }
            }
            catch
            {
            }
        }

        private static string ConvertSteamId3To64(long steamId3)
        {
            const long baseId = 76561197960265728L;
            return (baseId + steamId3).ToString();
        }

        private static string FormatAccountDetails(List<SteamAccountInfo> accounts)
        {
            List<string> lines = [];

            foreach (var account in accounts.Take(10))
            {
                string line = $"├─ {account.SteamId64}";

                if (!string.IsNullOrEmpty(account.AccountName))
                    line += $" | Name: {account.AccountName}";

                if (!string.IsNullOrEmpty(account.PersonaName))
                    line += $" | Display: {account.PersonaName}";

                if (account.LastLogin != DateTime.MinValue)
                    line += $" | Last Login: {account.LastLogin:yyyy-MM-dd}";
                else if (account.LastActivity != DateTime.MinValue)
                    line += $" | Last Activity: {account.LastActivity:yyyy-MM-dd}";

                lines.Add(line);
            }

            if (accounts.Count > 10)
            {
                lines.Add($"└─ ... and {accounts.Count - 10} more account(s)");
            }
            else if (lines.Count > 0)
            {
                lines[^1] = "└" + lines[^1].Substring(1);
            }

            return string.Join("\n", lines);
        }

        private static Dictionary<string, string> BuildMetadata(List<SteamAccountInfo> accounts)
        {
            Dictionary<string, string> metadata = new()
            {
                ["AccountCount"] = accounts.Count.ToString(),
                ["SteamIDs"] = string.Join(",", accounts.Select(a => a.SteamId64)),
                ["AccountNames"] = string.Join(",", accounts.Where(a => !string.IsNullOrEmpty(a.AccountName)).Select(a => a.AccountName))
            };

            for (int i = 0; i < Math.Min(5, accounts.Count); i++)
            {
                var acc = accounts[i];
                metadata[$"Account{i + 1}_SteamID"] = acc.SteamId64;
                if (!string.IsNullOrEmpty(acc.AccountName))
                    metadata[$"Account{i + 1}_Name"] = acc.AccountName;
            }

            return metadata;
        }

        private static string GetSteamInstallPath()
        {
            try
            {
                using RegistryKey? key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Valve\Steam");
                if (key != null)
                {
                    object? path = key.GetValue("SteamPath");
                    if (path != null)
                    {
                        return path.ToString() ?? string.Empty;
                    }
                }

                using RegistryKey? key64 = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\Valve\Steam");
                if (key64 != null)
                {
                    object? path = key64.GetValue("InstallPath");
                    if (path != null)
                    {
                        return path.ToString() ?? string.Empty;
                    }
                }
            }
            catch
            {
            }

            return string.Empty;
        }

        private class SteamAccountInfo
        {
            public string SteamId64 { get; set; } = string.Empty;
            public string AccountName { get; set; } = string.Empty;
            public string PersonaName { get; set; } = string.Empty;
            public DateTime LastLogin { get; set; } = DateTime.MinValue;
            public DateTime LastActivity { get; set; } = DateTime.MinValue;
        }
    }
}