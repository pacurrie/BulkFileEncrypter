namespace BulkFileEncrypter;

public interface INonceGenerator
{
    void RegisterNonce(byte[] nonce);
    byte[] GenerateNonce();
}

public class NonceGenerator : INonceGenerator
{
    private readonly IRandomGenerator _randomGenerator;
    private readonly HashSet<string> _exclusionList = new ();

    public NonceGenerator(IRandomGenerator randomGenerator)
    {
        _randomGenerator = randomGenerator;
    }

    public void RegisterNonce(byte[] nonce)
    {
        _exclusionList.Add(nonce.HexDump());
    }

    public byte[] GenerateNonce()
    {
        byte[] nonce;
        do
        {
            nonce = _randomGenerator.GenerateBytes(FileEncrypter.NonceLengthBytes);
        } while (_exclusionList.Contains(nonce.HexDump()));

        _exclusionList.Add(nonce.HexDump());

        return nonce;
    }
}