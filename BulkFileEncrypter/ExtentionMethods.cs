namespace BulkFileEncrypter;

public static class ExtentionMethods
{
    public static string HexDump(this byte[] buf)
    {
        return BitConverter.ToString(buf).Replace("-", string.Empty);
    }

    public static void Write(this Stream stream, byte[] buffer)
    {
        stream.Write(buffer, 0, buffer.Length);
    }
}