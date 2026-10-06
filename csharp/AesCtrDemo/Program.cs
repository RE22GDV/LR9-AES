// Лабораторна робота №9 — «Захист даних»
// AES у режимі CTR на C#: проста програма до основної частини на Python.
//
// Клас AesCtr підключено з solution/AesCtr.cs без копіювання.
//
// Запуск:
//   dotnet run --project csharp/AesCtrDemo                       — демонстрація
//   dotnet run --project csharp/AesCtrDemo -- "мій текст"         — зашифрувати й розшифрувати текст
//   dotnet run --project csharp/AesCtrDemo -- selftest            — офіційні вектори NIST
//   dotnet run --project csharp/AesCtrDemo -- ctr <ключ> <лічильник> <дані>   (усе в hex)
//   dotnet run -c Release --project csharp/AesCtrDemo -- bench               — швидкість CTR

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Lab9.AesCtrDemo;

public static class Program
{
    public static int Main(string[] args)
    {
        Console.OutputEncoding = new UTF8Encoding(false);
        if (args.Length == 0)
            return Demo("Лабораторна робота №9: AES у режимі CTR, зашифрування і розшифрування.");
        return args[0] switch
        {
            "selftest" => SelfTest(),
            "ctr" when args.Length == 4 => Ctr(args[1], args[2], args[3]),
            "bench" => Bench(),
            _ => Demo(string.Join(" ", args)),
        };
    }

    private static int Demo(string text)
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);      // AES-256
        byte[] counter = RandomNumberGenerator.GetBytes(16);  // унікальний для кожного повідомлення
        byte[] plaintext = Encoding.UTF8.GetBytes(text);

        byte[] ciphertext = AesCtr.Encrypt(plaintext, key, counter);
        byte[] restored = AesCtr.Decrypt(ciphertext, key, counter);

        Console.WriteLine($"Ключ (AES-256):   {Convert.ToHexString(key).ToLowerInvariant()}");
        Console.WriteLine($"Лічильник:        {Convert.ToHexString(counter).ToLowerInvariant()}");
        Console.WriteLine($"Відкритий текст:  {text}");
        Console.WriteLine($"Шифротекст (hex): {Convert.ToHexString(ciphertext).ToLowerInvariant()}");
        Console.WriteLine($"Розшифровано:     {Encoding.UTF8.GetString(restored)}");
        Console.WriteLine($"Довжина: {plaintext.Length} Б → {ciphertext.Length} Б (CTR не потребує доповнення)");

        // Для порівняння — режим CFB, який є в .NET (як CBC у прикладі з постановки).
        using Aes aesObject = Aes.Create();
        aesObject.Key = key;
        aesObject.Mode = CipherMode.CFB;
        aesObject.FeedbackSize = 8;
        byte[] cfb = aesObject.EncryptCfb(plaintext, counter, PaddingMode.None, 8);
        byte[] cfbBack = aesObject.DecryptCfb(cfb, counter, PaddingMode.None, 8);
        Console.WriteLine($"CFB-8 (.NET):     {Convert.ToHexString(cfb).ToLowerInvariant()}");
        Console.WriteLine($"CFB-8 назад:      {Encoding.UTF8.GetString(cfbBack)}");
        return restored.SequenceEqual(plaintext) && cfbBack.SequenceEqual(plaintext) ? 0 : 1;
    }

    /// <summary>Швидкість AesCtr (4 МіБ, медіана п'яти повторів) у форматі JSON.</summary>
    private static int Bench()
    {
        byte[] key = RandomNumberGenerator.GetBytes(16);
        byte[] counter = RandomNumberGenerator.GetBytes(16);
        byte[] data = RandomNumberGenerator.GetBytes(4 << 20);
        AesCtr.Encrypt(data, key, counter);                       // прогрівання
        var samples = new System.Collections.Generic.List<double>();
        for (int i = 0; i < 5; i++)
        {
            var sw = Stopwatch.StartNew();
            AesCtr.Encrypt(data, key, counter);
            samples.Add(data.Length / 1024.0 / sw.Elapsed.TotalSeconds);
        }
        samples.Sort();
        Console.WriteLine(JsonSerializer.Serialize(new
        {
            kib_per_s_median = samples[2],
            kib_per_s_all = samples,
            bytes = data.Length,
            dotnet = Environment.Version.ToString(),
        }));
        return 0;
    }

    private static int Ctr(string keyHex, string counterHex, string dataHex)
    {
        byte[] output = AesCtr.Encrypt(Convert.FromHexString(dataHex), Convert.FromHexString(keyHex),
                                       Convert.FromHexString(counterHex));
        Console.WriteLine(Convert.ToHexString(output).ToLowerInvariant());
        return 0;
    }

    private static string FindUp(string relative)
    {
        foreach (string start in new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory })
        {
            for (var dir = new DirectoryInfo(start); dir != null; dir = dir.Parent)
            {
                string candidate = Path.Combine(dir.FullName, relative);
                if (File.Exists(candidate)) return candidate;
            }
        }
        throw new FileNotFoundException(relative);
    }

    private static int SelfTest()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(FindUp(Path.Combine("tests", "vectors.json"))));
        int failures = 0, checkedCount = 0;
        foreach (var v in doc.RootElement.GetProperty("vectors").EnumerateArray())
        {
            string mode = v.GetProperty("mode").GetString()!;
            if (mode is not ("CTR" or "CFB" or "CFB8")) continue;
            byte[] key = Convert.FromHexString(v.GetProperty("key").GetString()!);
            byte[] iv = Convert.FromHexString(v.GetProperty("iv").GetString()!);
            byte[] pt = Convert.FromHexString(v.GetProperty("plaintext").GetString()!);
            byte[] ct = Convert.FromHexString(v.GetProperty("ciphertext").GetString()!);
            bool ok;
            if (mode == "CTR")
            {
                ok = AesCtr.Encrypt(pt, key, iv).SequenceEqual(ct) && AesCtr.Decrypt(ct, key, iv).SequenceEqual(pt);
            }
            else
            {
                using Aes aes = Aes.Create();
                aes.Key = key;
                int bits = mode == "CFB8" ? 8 : 128;
                ok = aes.EncryptCfb(pt, iv, PaddingMode.None, bits).SequenceEqual(ct)
                     && aes.DecryptCfb(ct, iv, PaddingMode.None, bits).SequenceEqual(pt);
            }
            checkedCount++;
            failures += ok ? 0 : 1;
            Console.WriteLine($"[{(ok ? "OK" : "FAIL")}] {v.GetProperty("source").GetString()}");
        }

        // Випадкові повідомлення довільної довжини: розшифрування повертає оригінал.
        int roundTrips = 0;
        for (int i = 0; i < 1000; i++)
        {
            byte[] key = RandomNumberGenerator.GetBytes(16 + 8 * (i % 3));
            byte[] counter = RandomNumberGenerator.GetBytes(16);
            byte[] data = RandomNumberGenerator.GetBytes(i % 100);
            if (AesCtr.Decrypt(AesCtr.Encrypt(data, key, counter), key, counter).SequenceEqual(data)) roundTrips++;
        }
        Console.WriteLine($"випадкові повідомлення 0–99 байтів: збіг {roundTrips} з 1000");
        failures += roundTrips == 1000 ? 0 : 1;

        // Перенесення лічильника через усі 128 бітів: ff…ff → 00…00.
        byte[] wrapKey = new byte[16];
        byte[] ff = Enumerable.Repeat((byte)0xff, 16).ToArray();
        byte[] twoBlocks = AesCtr.Encrypt(new byte[32], wrapKey, ff);
        byte[] secondFromZero = AesCtr.Encrypt(new byte[16], wrapKey, new byte[16]);
        bool wraps = twoBlocks.Skip(16).SequenceEqual(secondFromZero);
        Console.WriteLine($"лічильник ff…ff переходить у 00…00: {(wraps ? "так" : "ні")}");
        failures += wraps ? 0 : 1;

        Console.WriteLine(failures == 0 ? $"пройдено все ({checkedCount} векторів NIST)" : $"FAIL: {failures}");
        return failures == 0 ? 0 : 1;
    }
}
