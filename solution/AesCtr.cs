using System;
using System.Security.Cryptography;

// AES in CTR (counter) mode built on top of System.Security.Cryptography.Aes.
// .NET has no CipherMode.CTR, so the mode itself is implemented here:
// keystream block i = AES_K(counter + i), ciphertext = plaintext XOR keystream.
// The same operation both encrypts and decrypts.
public static class AesCtr
{
    public static byte[] Encrypt(byte[] plaintext, byte[] key, byte[] counter)
    {
        return Transform(plaintext, key, counter);
    }

    public static byte[] Decrypt(byte[] ciphertext, byte[] key, byte[] counter)
    {
        return Transform(ciphertext, key, counter);
    }

    private static byte[] Transform(byte[] input, byte[] key, byte[] initialCounter)
    {
        if (initialCounter.Length != 16)
            throw new ArgumentException("The counter block must be 16 bytes.");

        using Aes aesObject = Aes.Create();
        aesObject.Key = key;                      // 16, 24 or 32 bytes: AES-128/192/256
        aesObject.Mode = CipherMode.ECB;          // raw AES block function; CTR is below
        aesObject.Padding = PaddingMode.None;     // stream mode: no padding needed

        byte[] counter = (byte[])initialCounter.Clone();
        byte[] keystream = new byte[16];
        byte[] output = new byte[input.Length];

        for (int offset = 0; offset < input.Length; offset += 16)
        {
            aesObject.EncryptEcb(counter, keystream, PaddingMode.None);
            int count = Math.Min(16, input.Length - offset);
            for (int i = 0; i < count; i++)
                output[offset + i] = (byte)(input[offset + i] ^ keystream[i]);
            Increment(counter);
        }
        return output;
    }

    // 128-bit big-endian increment, as in NIST SP 800-38A.
    private static void Increment(byte[] counter)
    {
        for (int i = counter.Length - 1; i >= 0; i--)
        {
            if (++counter[i] != 0)
                break;
        }
    }
}
