namespace BulkFileEncrypter;

public class BufferWrapper
{
    public readonly byte[] Buffer;
    private int _current;

    public BufferWrapper(int size)
    {
        Buffer = new byte[size];
    }

    public void CopyBuffer(byte[] buf)
    {
        buf.CopyTo(Buffer, _current);
        _current += buf.Length;
    }

    public bool ReadStream(Stream inputStream, int readBytes)
    {
        if (inputStream.Read(Buffer, _current, readBytes) != readBytes)
            return false;
        
        _current += readBytes;

        return true;
    }
}