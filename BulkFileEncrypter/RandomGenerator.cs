using System.Security.Cryptography;

namespace BulkFileEncrypter;

public interface IRandomGenerator
{
    public byte[] GenerateBytes(int numBytes);
}

public sealed class RandomGenerator : IRandomGenerator, IDisposable
{
    private readonly RandomNumberGenerator _rng;
    
    public RandomGenerator()
    {
        _rng = RandomNumberGenerator.Create();
    }
    
    public byte[] GenerateBytes(int numBytes)
    {
        if (numBytes > 256) throw new NotSupportedException("Cannot generate more than 256 random bytes in one method call");
        
        var buf = new byte[numBytes];

        _rng.GetBytes(buf);
        
        return buf;
    }

    public void Dispose()
    {
        _rng.Dispose();
    }
}