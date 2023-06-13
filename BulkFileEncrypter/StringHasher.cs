using System.Security.Cryptography;
using System.Text;

namespace BulkFileEncrypter;

public interface IStringHasher
{
    string HashString(string str);
}

public sealed class StringHasher : IStringHasher, IDisposable
{
    private readonly SHA256 _hasher;
    
    public StringHasher()
    {
        _hasher = SHA256.Create();
    }
    
    public string HashString(string str)
    {
        var bytes = Encoding.UTF8.GetBytes(str);

        return _hasher.ComputeHash(bytes).HexDump();
    }

    public void Dispose()
    {
        _hasher.Dispose();
    }
}