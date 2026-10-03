using System.IO;
using System.Text.Json;
using NTE_unlockfps.Models;

namespace NTE_unlockfps.Services
{
    public class ConfigService
    {
        private readonly string _configFilePath;

        public ConfigService()
        {
            _configFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "NTE_config.json");
        }

        public EFConfig LoadConfig()
        {
            if (!File.Exists(_configFilePath))
            {
                var defaultConfig = new EFConfig();
                SaveConfig(defaultConfig);
                return defaultConfig;
            }

            try
            {
                var json = File.ReadAllText(_configFilePath);
                var config = JsonSerializer.Deserialize<EFConfig>(json);
                return config ?? new EFConfig();
            }
            catch
            {
                return new EFConfig();
            }
        }

        public void SaveConfig(EFConfig config)
        {
            var options = new JsonSerializerOptions
            {
                WriteIndented = true
            };
            var json = JsonSerializer.Serialize(config, options);
            File.WriteAllText(_configFilePath, json);
        }
    }
}
