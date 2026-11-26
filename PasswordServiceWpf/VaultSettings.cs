using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace PasswordServiceWpf;

public static class VaultSettings
{
    public static string DefaultDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "PasswordSaver");

    public static string DefaultVaultFile => Path.Combine(DefaultDirectory, "passwords.enc");
    public static string SettingsFile => Path.Combine(DefaultDirectory, "settings.json");

    public static (string VaultPath, bool Configured) LoadVaultLocation(string? settingsPath = null)
    {
        var cfgPath = settingsPath ?? SettingsFile;
        if (!File.Exists(cfgPath))
            return (DefaultVaultFile, false);

        try
        {
            var json = File.ReadAllText(cfgPath, Encoding.UTF8);
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("vault_directory", out var dirEl) || dirEl.ValueKind != JsonValueKind.String)
                throw new InvalidDataException("密码库位置配置无效");
            var dir = dirEl.GetString();
            if (string.IsNullOrWhiteSpace(dir))
                throw new InvalidDataException("密码库位置配置无效");
            return (Path.Combine(dir, "passwords.enc"), true);
        }
        catch (Exception ex) when (ex is IOException or JsonException or InvalidDataException)
        {
            throw new InvalidDataException("密码库位置配置无效", ex);
        }
    }

    public static void SaveVaultLocation(string directory, string? settingsPath = null)
    {
        var cfgPath = settingsPath ?? SettingsFile;
        var payload = JsonSerializer.Serialize(new Dictionary<string, string> { ["vault_directory"] = directory }, new JsonSerializerOptions { WriteIndented = true }) + "\n";
        VaultCore.AtomicWrite(cfgPath, Encoding.UTF8.GetBytes(payload));
    }

    public static string MigrateVault(string sourcePath, string targetDirectory, string masterPassword, IReadOnlyList<PasswordRecord> expectedRecords)
    {
        var targetPath = Path.Combine(targetDirectory, "passwords.enc");
        if (File.Exists(targetPath))
            throw new IOException("目标位置已存在密码库，请选择其他文件夹");

        Directory.CreateDirectory(targetDirectory);
        var tempPath = Path.Combine(targetDirectory, $".passwords-{Guid.NewGuid():N}.enc.tmp");
        try
        {
            File.Copy(sourcePath, tempPath, overwrite: false);
            var verified = VaultCore.LoadVault(tempPath, masterPassword);
            if (!verified.SequenceEqual(expectedRecords))
                throw new InvalidDataException("目标密码库校验失败");
            File.Move(tempPath, targetPath, overwrite: false);
            return targetPath;
        }
        catch
        {
            try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
            throw;
        }
    }
}
