using SentinelAC.Core.Models;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Serialization;

namespace SentinelAC.Services
{
    public sealed class DiscordWebhookService
    {
        private static readonly HttpClient _httpClient = new HttpClient();
        private static readonly SemaphoreSlim _rateLimiter = new SemaphoreSlim(1, 1);
        private static DateTime _lastSendTime = DateTime.MinValue;
        private const int MIN_SEND_INTERVAL_SECONDS = 10;

        private static readonly byte[] _obfuscationKey = [0x53, 0x65, 0x6E, 0x74, 0x69, 0x6E, 0x65, 0x6C];

        private static string DecryptWebhookUrl()
        {
            byte[] encryptedData = Convert.FromBase64String(
                "aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTQzNDIwNjkyMTQ4ODg2MzQ0Ni9rRjI4YU9aYXRxUC1SXzJnb2xLX2VzY2gtQ3UwZUJUbV9FUTM3UENiZmN3U2tocXJYZ2tWbklNbkxtTTZIR1E2b2lU"
            );

            StringBuilder decrypted = new StringBuilder();
            for (int i = 0; i < encryptedData.Length; i++)
            {
                decrypted.Append((char)(encryptedData[i] ^ _obfuscationKey[i % _obfuscationKey.Length]));
            }

            return Encoding.UTF8.GetString(Convert.FromBase64String(decrypted.ToString()));
        }

        public async Task<bool> SendReportAsync(ScanReport report)
        {
            await _rateLimiter.WaitAsync();

            try
            {
                TimeSpan timeSinceLastSend = DateTime.Now - _lastSendTime;
                if (timeSinceLastSend.TotalSeconds < MIN_SEND_INTERVAL_SECONDS)
                {
                    int waitTime = (int)(MIN_SEND_INTERVAL_SECONDS - timeSinceLastSend.TotalSeconds);
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"Rate limit: Waiting {waitTime} seconds before sending...");
                    Console.ResetColor();
                    await Task.Delay(waitTime * 1000);
                }

                string webhookUrl = DecryptWebhookUrl();
                DiscordWebhookPayload payload = CreatePayload(report);

                HttpResponseMessage response = await _httpClient.PostAsJsonAsync(webhookUrl, payload);

                _lastSendTime = DateTime.Now;

                if (response.IsSuccessStatusCode)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("✓ Report successfully sent to Discord");
                    Console.ResetColor();
                    return true;
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"✗ Failed to send report: {response.StatusCode}");
                    Console.ResetColor();
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"✗ Error sending to Discord: {ex.Message}");
                Console.ResetColor();
                return false;
            }
            finally
            {
                _rateLimiter.Release();
            }
        }

        private DiscordWebhookPayload CreatePayload(ScanReport report)
        {
            DiscordEmbed embed = new DiscordEmbed
            {
                Title = "🛡️ SentinelAC - Scan Report",
                Color = GetColorForThreatLevel(report.OverallThreatLevel),
                Timestamp = DateTime.UtcNow.ToString("o"),
                Fields = []
            };

            embed.Fields.Add(new DiscordEmbedField
            {
                Name = "⚠️ Threat Level",
                Value = $"**{report.OverallThreatLevel}**",
                Inline = true
            });

            embed.Fields.Add(new DiscordEmbedField
            {
                Name = "🔍 Total Checks",
                Value = report.TotalChecks.ToString(),
                Inline = true
            });

            embed.Fields.Add(new DiscordEmbedField
            {
                Name = "⏱️ Scan Duration",
                Value = $"{report.Duration.TotalSeconds:F2}s",
                Inline = true
            });

            embed.Fields.Add(new DiscordEmbedField
            {
                Name = "🎯 Detection Summary",
                Value = GetDetectionSummary(report),
                Inline = false
            });

            if (report.HighConfidenceDetections > 0)
            {
                embed.Fields.Add(new DiscordEmbedField
                {
                    Name = "🔴 High Confidence Threats",
                    Value = GetHighConfidenceThreats(report),
                    Inline = false
                });
            }

            embed.Fields.Add(new DiscordEmbedField
            {
                Name = "💻 System Info",
                Value = $"**Machine:** {Environment.MachineName}\n**User:** {Environment.UserName}\n**OS:** {Environment.OSVersion}",
                Inline = false
            });

            embed.Footer = new DiscordEmbedFooter
            {
                Text = "SentinelAC v1.2 | Advanced Anti-Cheat Detection"
            };

            return new DiscordWebhookPayload
            {
                Username = "SentinelAC",
                AvatarUrl = "https://cdn.discordapp.com/embed/avatars/0.png",
                Embeds = [embed]
            };
        }

        private int GetColorForThreatLevel(ThreatLevel level)
        {
            return level switch
            {
                ThreatLevel.None => 0x00FF00,
                ThreatLevel.Low => 0xFFFF00,
                ThreatLevel.Medium => 0xFF9900,
                ThreatLevel.High => 0xFF3300,
                ThreatLevel.Critical => 0xFF0000,
                _ => 0x808080
            };
        }

        private string GetDetectionSummary(ScanReport report)
        {
            if (!report.Detections.Any())
                return "✅ **No threats detected** - System appears clean";

            Dictionary<DetectionType, int> grouped = report.Detections
                .GroupBy(d => d.Type)
                .ToDictionary(g => g.Key, g => g.Count());

            StringBuilder summary = new StringBuilder();

            foreach (KeyValuePair<DetectionType, int> group in grouped.OrderByDescending(g => g.Value))
            {
                string emoji = GetEmojiForDetectionType(group.Key);
                summary.AppendLine($"{emoji} **{group.Key}**: {group.Value}");
            }

            return summary.ToString();
        }

        private string GetHighConfidenceThreats(ScanReport report)
        {
            List<DetectionResult> threats = report.GetHighConfidenceThreats().Take(5).ToList();

            if (!threats.Any())
                return "None";

            StringBuilder result = new StringBuilder();

            foreach (DetectionResult threat in threats)
            {
                string levelEmoji = threat.Level switch
                {
                    ThreatLevel.Critical => "🔴",
                    ThreatLevel.High => "🟠",
                    _ => "🟡"
                };

                result.AppendLine($"{levelEmoji} **{threat.Description}**");
                result.AppendLine($"   ↳ Confidence: {threat.ConfidenceScore:P0}");
            }

            if (report.HighConfidenceDetections > 5)
                result.AppendLine($"\n*...and {report.HighConfidenceDetections - 5} more*");

            return result.ToString();
        }

        private string GetEmojiForDetectionType(DetectionType type)
        {
            return type switch
            {
                DetectionType.Process => "⚙️",
                DetectionType.Module => "📦",
                DetectionType.Driver => "🔧",
                DetectionType.Network => "🌐",
                DetectionType.MemoryScanner => "🧠",
                DetectionType.InputManipulation => "🖱️",
                DetectionType.Registry => "📝",
                DetectionType.SystemManipulation => "⚠️",
                DetectionType.Virtualization => "💻",
                DetectionType.Sandbox => "🔒",
                _ => "📋"
            };
        }

        private sealed class DiscordWebhookPayload
        {
            [JsonPropertyName("username")]
            public string Username { get; set; } = string.Empty;

            [JsonPropertyName("avatar_url")]
            public string AvatarUrl { get; set; } = string.Empty;

            [JsonPropertyName("embeds")]
            public List<DiscordEmbed> Embeds { get; set; } = [];
        }

        private sealed class DiscordEmbed
        {
            [JsonPropertyName("title")]
            public string Title { get; set; } = string.Empty;

            [JsonPropertyName("color")]
            public int Color { get; set; }

            [JsonPropertyName("fields")]
            public List<DiscordEmbedField> Fields { get; set; } = [];

            [JsonPropertyName("footer")]
            public DiscordEmbedFooter? Footer { get; set; }

            [JsonPropertyName("timestamp")]
            public string Timestamp { get; set; } = string.Empty;
        }

        private sealed class DiscordEmbedField
        {
            [JsonPropertyName("name")]
            public string Name { get; set; } = string.Empty;

            [JsonPropertyName("value")]
            public string Value { get; set; } = string.Empty;

            [JsonPropertyName("inline")]
            public bool Inline { get; set; }
        }

        private sealed class DiscordEmbedFooter
        {
            [JsonPropertyName("text")]
            public string Text { get; set; } = string.Empty;
        }
    }
}
