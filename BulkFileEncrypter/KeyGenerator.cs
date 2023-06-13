namespace BulkFileEncrypter;

public interface IKeyGenerator
{
    EncryptionKey Generate();
}

public class KeyGenerator : IKeyGenerator
{
    private readonly IRandomGenerator _rng;

    public KeyGenerator(IRandomGenerator rng)
    {
        _rng = rng;
    }
    
    public EncryptionKey Generate()
    {
        return new EncryptionKey(_rng.GenerateBytes(EncryptionKey.KeyLengthBytes));
    }
}