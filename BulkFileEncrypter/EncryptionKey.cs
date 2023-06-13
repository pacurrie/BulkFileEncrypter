using System.CommandLine.Parsing;

namespace BulkFileEncrypter;

public class EncryptionKey
{
    public const int KeyLengthBytes = 32;

    public byte[] Key { get; private set; } = new byte[KeyLengthBytes];

    public EncryptionKey(byte[] keyBytes)
    {
        if (keyBytes.Length != KeyLengthBytes) throw new NotSupportedException("Invalid key length");
        keyBytes.CopyTo(Key, 0);
    }

    public EncryptionKey(string base64) : this(Convert.FromBase64String(base64))
    {
    }

    public string ToBase64() => Convert.ToBase64String(Key);

    public string GetPaddingString() => BitConverter.ToString(new[] { Key[0] });

    public static EncryptionKey Parse(ArgumentResult args)
    {
        return new EncryptionKey(args.Tokens[0].Value);
    }
}