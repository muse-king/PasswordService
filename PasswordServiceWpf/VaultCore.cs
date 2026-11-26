using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Konscious.Security.Cryptography;

namespace PasswordServiceWpf;

public sealed record PasswordRecord(string Name, string Password);

public sealed class VaultAuthenticationException : Exception
{
    public VaultAuthenticationException(string message, Exception? inner = null) : base(message, inner) { }
}

public static class VaultCore
{
    public const int VaultVersion = 1;
    public const string KdfName = "Argon2id";
    public const string CipherName = "AES-256-GCM";
    public const int KeyLength = 32;
    public const int SaltLength = 16;
    public const int NonceLength = 12;
    public const int TagLength = 16;

    public const int MinMemoryCostKib = 8 * 1024;
    public const int MaxMemoryCostKib = 256 * 1024;
    public const int MinIterations = 1;
    public const int MaxIterations = 10;
    public const int MinLanes = 1;
    public const int MaxLanes = 16;

    public const int DefaultMemoryCostKib = 64 * 1024;
    public const int DefaultIterations = 3;
    public const int DefaultLanes = 4;

    private const string GenericAuthError = "Invalid master password or corrupted vault";
    private static readonly int MinCiphertextLength = TagLength + Encoding.UTF8.GetByteCount("{\"records\":[]}");

    private static readonly JsonSerializerOptions CompactJsonOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        WriteIndented = false,
    };

    private static readonly JsonSerializerOptions EnvelopeWriteOptions = new()
    {
        WriteIndented = true,
    };

    public static byte[] DeriveKey(string masterPassword, byte[] salt, int memoryCostKib, int iterations, int lanes)
    {
        if (string.IsNullOrEmpty(masterPassword))
            throw new ArgumentException("Master password must not be empty", nameof(masterPassword));

        var passwordBytes = Encoding.UTF8.GetBytes(masterPassword);
        try
        {
            using var argon2 = new Argon2id(passwordBytes)
            {
                Salt = salt,
                DegreeOfParallelism = lanes,
                Iterations = iterations,
                MemorySize = memoryCostKib,
            };
            return argon2.GetBytes(KeyLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    private static byte[] BuildAssociatedData(int version, string kdfName, int memoryCostKib, int iterations, int lanes, string saltB64, string cipher)
    {
        // Matches Python: json.dumps(metadata, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        var aadJson = $"{{\"cipher\":\"{cipher}\",\"kdf\":{{\"iterations\":{iterations},\"lanes\":{lanes},\"memory_cost_kib\":{memoryCostKib},\"name\":\"{kdfName}\"}},\"salt\":\"{saltB64}\",\"version\":{version}}}";
        return Encoding.UTF8.GetBytes(aadJson);
    }

    public static string EncryptVaultToJson(string masterPassword, IEnumerable<PasswordRecord> records)
    {
        if (string.IsNullOrEmpty(masterPassword))
            throw new ArgumentException("Master password must not be empty", nameof(masterPassword));

        var recordList = records.Select(r => new Dictionary<string, string>
        {
            ["name"] = r.Name ?? throw new ArgumentNullException(nameof(r.Name)),
            ["password"] = r.Password ?? throw new ArgumentNullException(nameof(r.Password)),
        }).ToList();

        var payloadObj = new Dictionary<string, object> { ["records"] = recordList };
        var payloadBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payloadObj, CompactJsonOptions));

        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        var nonce = RandomNumberGenerator.GetBytes(NonceLength);
        var saltB64 = Convert.ToBase64String(salt);
        var nonceB64 = Convert.ToBase64String(nonce);

        var aad = BuildAssociatedData(VaultVersion, KdfName, DefaultMemoryCostKib, DefaultIterations, DefaultLanes, saltB64, CipherName);
        var key = DeriveKey(masterPassword, salt, DefaultMemoryCostKib, DefaultIterations, DefaultLanes);

        var combined = new byte[payloadBytes.Length + TagLength];
        try
        {
            using var aes = new AesGcm(key, TagLength);
            var cipherSpan = combined.AsSpan(0, payloadBytes.Length);
            var tagSpan = combined.AsSpan(payloadBytes.Length, TagLength);
            aes.Encrypt(nonce, payloadBytes, cipherSpan, tagSpan, aad);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(payloadBytes);
        }

        var envelope = new SortedDictionary<string, object>
        {
            ["cipher"] = CipherName,
            ["ciphertext"] = Convert.ToBase64String(combined),
            ["kdf"] = new SortedDictionary<string, object>
            {
                ["iterations"] = DefaultIterations,
                ["lanes"] = DefaultLanes,
                ["memory_cost_kib"] = DefaultMemoryCostKib,
                ["name"] = KdfName,
            },
            ["nonce"] = nonceB64,
            ["salt"] = saltB64,
            ["version"] = VaultVersion,
        };

        return JsonSerializer.Serialize(envelope, EnvelopeWriteOptions) + "\n";
    }

    public static List<PasswordRecord> DecryptVaultFromJson(string masterPassword, string jsonText)
    {
        if (string.IsNullOrEmpty(masterPassword))
            throw new ArgumentException("Master password must not be empty", nameof(masterPassword));

        try
        {
            using var doc = JsonDocument.Parse(jsonText);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                throw new VaultAuthenticationException(GenericAuthError);

            if (!root.TryGetProperty("version", out var versionEl) || versionEl.ValueKind != JsonValueKind.Number || !versionEl.TryGetInt32(out var version) || version != VaultVersion)
                throw new VaultAuthenticationException(GenericAuthError);

            if (!root.TryGetProperty("cipher", out var cipherEl) || cipherEl.ValueKind != JsonValueKind.String || cipherEl.GetString() != CipherName)
                throw new VaultAuthenticationException(GenericAuthError);

            if (!root.TryGetProperty("kdf", out var kdfEl) || kdfEl.ValueKind != JsonValueKind.Object)
                throw new VaultAuthenticationException(GenericAuthError);

            if (!kdfEl.TryGetProperty("name", out var kdfNameEl) || kdfNameEl.ValueKind != JsonValueKind.String || kdfNameEl.GetString() != KdfName)
                throw new VaultAuthenticationException(GenericAuthError);

            if (!kdfEl.TryGetProperty("memory_cost_kib", out var memEl) || memEl.ValueKind != JsonValueKind.Number || !memEl.TryGetInt32(out var memoryCost) || memoryCost < MinMemoryCostKib || memoryCost > MaxMemoryCostKib)
                throw new VaultAuthenticationException(GenericAuthError);

            if (!kdfEl.TryGetProperty("iterations", out var iterEl) || iterEl.ValueKind != JsonValueKind.Number || !iterEl.TryGetInt32(out var iterations) || iterations < MinIterations || iterations > MaxIterations)
                throw new VaultAuthenticationException(GenericAuthError);

            if (!kdfEl.TryGetProperty("lanes", out var lanesEl) || lanesEl.ValueKind != JsonValueKind.Number || !lanesEl.TryGetInt32(out var lanes) || lanes < MinLanes || lanes > MaxLanes)
                throw new VaultAuthenticationException(GenericAuthError);

            if (!root.TryGetProperty("salt", out var saltEl) || saltEl.ValueKind != JsonValueKind.String)
                throw new VaultAuthenticationException(GenericAuthError);
            var saltB64 = saltEl.GetString()!;
            var salt = Convert.FromBase64String(saltB64);
            if (salt.Length != SaltLength)
                throw new VaultAuthenticationException(GenericAuthError);

            if (!root.TryGetProperty("nonce", out var nonceEl) || nonceEl.ValueKind != JsonValueKind.String)
                throw new VaultAuthenticationException(GenericAuthError);
            var nonce = Convert.FromBase64String(nonceEl.GetString()!);
            if (nonce.Length != NonceLength)
                throw new VaultAuthenticationException(GenericAuthError);

            if (!root.TryGetProperty("ciphertext", out var ctEl) || ctEl.ValueKind != JsonValueKind.String)
                throw new VaultAuthenticationException(GenericAuthError);
            var combined = Convert.FromBase64String(ctEl.GetString()!);
            if (combined.Length < MinCiphertextLength)
                throw new VaultAuthenticationException(GenericAuthError);

            var aad = BuildAssociatedData(version, KdfName, memoryCost, iterations, lanes, saltB64, CipherName);
            var key = DeriveKey(masterPassword, salt, memoryCost, iterations, lanes);

            var cipherLen = combined.Length - TagLength;
            var plaintext = new byte[cipherLen];
            try
            {
                using var aes = new AesGcm(key, TagLength);
                aes.Decrypt(nonce, combined.AsSpan(0, cipherLen), combined.AsSpan(cipherLen, TagLength), plaintext, aad);

                var payloadJson = Encoding.UTF8.GetString(plaintext);
                using var payloadDoc = JsonDocument.Parse(payloadJson);
                if (!payloadDoc.RootElement.TryGetProperty("records", out var recordsEl) || recordsEl.ValueKind != JsonValueKind.Array)
                    throw new VaultAuthenticationException(GenericAuthError);

                var result = new List<PasswordRecord>();
                foreach (var item in recordsEl.EnumerateArray())
                {
                    if (item.ValueKind != JsonValueKind.Object ||
                        !item.TryGetProperty("name", out var nEl) || nEl.ValueKind != JsonValueKind.String ||
                        !item.TryGetProperty("password", out var pEl) || pEl.ValueKind != JsonValueKind.String)
                    {
                        throw new VaultAuthenticationException(GenericAuthError);
                    }
                    result.Add(new PasswordRecord(nEl.GetString()!, pEl.GetString()!));
                }
                return result;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        catch (VaultAuthenticationException)
        {
            throw;
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or JsonException)
        {
            throw new VaultAuthenticationException(GenericAuthError, ex);
        }
    }

    public static List<PasswordRecord> LoadVault(string path, string masterPassword)
    {
        var jsonText = File.ReadAllText(path, Encoding.UTF8);
        return DecryptVaultFromJson(masterPassword, jsonText);
    }

    public static void SaveVault(string path, string masterPassword, IEnumerable<PasswordRecord> records)
    {
        var jsonText = EncryptVaultToJson(masterPassword, records);
        var data = Encoding.UTF8.GetBytes(jsonText);
        AtomicWrite(path, data);
    }

    public static void CreateVault(string path, string masterPassword, IEnumerable<PasswordRecord>? records = null)
    {
        if (File.Exists(path))
            throw new IOException($"Vault already exists: {path}");
        SaveVault(path, masterPassword, records ?? Array.Empty<PasswordRecord>());
    }

    public static void AtomicWrite(string path, byte[] data)
    {
        var fullPath = Path.GetFullPath(path);
        var dir = Path.GetDirectoryName(fullPath)!;
        Directory.CreateDirectory(dir);
        var tempPath = Path.Combine(dir, $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var fs = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                fs.Write(data, 0, data.Length);
                fs.Flush(true);
            }
            File.Move(tempPath, fullPath, overwrite: true);
        }
        catch
        {
            try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
            throw;
        }
    }
}
