using System.Security.Cryptography;
using System.Text;

if (args is not [var mode, var path] || mode is not ("seal" or "open")) return 2;
byte[] key = File.ReadAllBytes(Environment.GetEnvironmentVariable("SAMPLE_KEY_FILE")!);
using var cipher = new AesGcm(key, 16);
byte[] context = Encoding.UTF8.GetBytes(path);
string input = await Console.In.ReadToEndAsync();
try
{
    if (mode == "seal")
    {
        byte[] data = Encoding.UTF8.GetBytes(input);
        byte[] output = new byte[12 + data.Length + 16];
        RandomNumberGenerator.Fill(output.AsSpan(0, 12));
        cipher.Encrypt(output.AsSpan(0, 12), data, output.AsSpan(12, data.Length), output.AsSpan(12 + data.Length), context);
        Console.Write(Convert.ToBase64String(output));
    }
    else
    {
        byte[] data = Convert.FromBase64String(input);
        if (data.Length is < 28 or > 65536) return 1;
        byte[] output = new byte[data.Length - 28];
        cipher.Decrypt(data.AsSpan(0, 12), data.AsSpan(12, output.Length), data.AsSpan(12 + output.Length), output, context);
        Console.Write(Encoding.UTF8.GetString(output));
    }
    return 0;
}
catch (CryptographicException) { Console.Error.WriteLine("Signal authentication failed."); return 1; }
finally { CryptographicOperations.ZeroMemory(key); }
