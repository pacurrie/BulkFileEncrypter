using System.Security.Cryptography;
using System.Text;

namespace BulkFileEncrypter;


public interface IFileEncrypter
{
    EncryptionResult Encrypt(UnencryptedFile file, EncryptionKey key);
    EncryptionResult Decrypt(EncryptedFile file, EncryptionKey key);

    byte[]? GetNonce(string file);
}

public enum ErrorType
{
    NoError = 0,
    FileNoExist = 1,
    OutDirMissing = 2,
    NotAnEncryptedFile = 3,
    FailedToReadFile = 4,
    EncryptionError = 5
}

public class EncryptionResult
{
    public ErrorType Error { get; init; } = ErrorType.NoError;
    public string ErrorText { get; init; } = "";
    public string OutputFilename { get; init; } = "";
    public int ProcessedBytes { get; init; } = 0;

    public bool Ok => Error == ErrorType.NoError;
    
    public static EncryptionResult Failed(ErrorType et, string message = "")
    {
        return new EncryptionResult {
            Error = et,
            ErrorText = message,
        };
    }
}



public class FileEncrypter : IFileEncrypter
{
    public const int NonceLengthBytes = 12;
    private readonly INonceGenerator _nonceGenerator;
    private readonly IRandomGenerator _randomGenerator;
    private static readonly List<byte> OuterMagicHeader = new List<byte> { 0xa9, 0x9f, 0xc4, 0x2a };
    private const int tagLengthBytes = 16;
    private const int blockSizeBytes = 64;

    public FileEncrypter(INonceGenerator nonceGenerator, IRandomGenerator randomGenerator)
    {
        _nonceGenerator = nonceGenerator;
        _randomGenerator = randomGenerator;
    }
    
    public EncryptionResult Encrypt(UnencryptedFile file, EncryptionKey key)
    {
        if (!File.Exists(file.SrcAbs)) return EncryptionResult.Failed(ErrorType.FileNoExist);

        var outputFileName = Path.Combine(file.DstPath, file.DstName);
        var outputDir = Path.GetDirectoryName(outputFileName);
        if (string.IsNullOrWhiteSpace(outputDir)) return EncryptionResult.Failed(ErrorType.OutDirMissing);
        Directory.CreateDirectory(outputDir);

        var inputLength = (int) new FileInfo(file.SrcAbs).Length;
        
        var nonce = _nonceGenerator.GenerateNonce();
        var tag = new byte[tagLengthBytes];
        var fileNameBuffer = Encoding.UTF8.GetBytes(file.SrcName);

        var bufSize = inputLength + blockSizeBytes + fileNameBuffer.Length + sizeof(int);
        var plaintextBuffer = new BufferWrapper(bufSize);
        var encryptedBuffer = new byte[bufSize];
        

        // Create buffer to be encrypted
        plaintextBuffer.CopyBuffer(_randomGenerator.GenerateBytes(blockSizeBytes)); // Fill encryption buffer with one block size of random noise
        plaintextBuffer.CopyBuffer(BitConverter.GetBytes(fileNameBuffer.Length));
        plaintextBuffer.CopyBuffer(fileNameBuffer);
        
        using (var inStream = File.Open(file.SrcAbs, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            if (plaintextBuffer.ReadStream(inStream, inputLength) == false)
                return EncryptionResult.Failed(ErrorType.FailedToReadFile);
        }

        // Encrypt buffer
        using (var encryptor = new ChaCha20Poly1305(key.Key))
        {
            try
            {
                encryptor.Encrypt(nonce, plaintextBuffer.Buffer, encryptedBuffer, tag);
            }
            catch (CryptographicException ex)
            {
                return EncryptionResult.Failed(ErrorType.EncryptionError, ex.Message);
            }
        }

        // Create output file
        using (var outputFile = File.OpenWrite(outputFileName))
        {
            outputFile.Write(OuterMagicHeader.ToArray());
            outputFile.Write(nonce);
            outputFile.Write(tag);
            outputFile.Write(encryptedBuffer);
        }

        return new EncryptionResult { OutputFilename = outputFileName, ProcessedBytes = inputLength};
    }

    public EncryptionResult Decrypt(EncryptedFile file, EncryptionKey key)
    {
        if (!File.Exists(file.SrcFile)) return EncryptionResult.Failed(ErrorType.FileNoExist);

        var inputLength = (int) new FileInfo(file.SrcFile).Length;
        
        // Open encrypted file
        using var inputFile = File.OpenRead(file.SrcFile);

        var tempBuf = new byte[OuterMagicHeader.Count];
        if (inputFile.Read(tempBuf, 0, OuterMagicHeader.Count) != OuterMagicHeader.Count) return EncryptionResult.Failed(ErrorType.FailedToReadFile);
        if (tempBuf.SequenceEqual(OuterMagicHeader) == false) return EncryptionResult.Failed(ErrorType.NotAnEncryptedFile);

        var nonce = new byte[NonceLengthBytes];
        if (inputFile.Read(nonce, 0, NonceLengthBytes) != NonceLengthBytes) return EncryptionResult.Failed(ErrorType.FailedToReadFile);
        var tag = new byte[tagLengthBytes];
        if (inputFile.Read(tag, 0, tagLengthBytes) != tagLengthBytes) return EncryptionResult.Failed(ErrorType.FailedToReadFile);

        var encryptedLength = inputLength - (OuterMagicHeader.Count + NonceLengthBytes + tagLengthBytes);
        var encryptedBuffer = new BufferWrapper(encryptedLength);// buffers = _bufferProvider.GetBuffer(encryptedLength, 1);
        var decryptedBuffer = new byte[encryptedLength];

        encryptedBuffer.ReadStream(inputFile, encryptedLength);

        // Decrypt buffer
        using (var decryptor = new ChaCha20Poly1305(key.Key))
        {
            try
            {
                decryptor.Decrypt(nonce, encryptedBuffer.Buffer, tag, decryptedBuffer);
            }
            catch (CryptographicException ex)
            {
                return EncryptionResult.Failed(ErrorType.EncryptionError, ex.Message);
            }
        }

        // Get original filename
        var fileNameLength = BitConverter.ToInt32(decryptedBuffer, blockSizeBytes);
        var fileName = Encoding.UTF8.GetString(decryptedBuffer, blockSizeBytes + 4, fileNameLength);

        var subPath = Path.GetDirectoryName(fileName);
        if (string.IsNullOrWhiteSpace(subPath) == false)
        {
            Directory.CreateDirectory(Path.Combine(file.DstPath, subPath));
        }
        
        using (var outputFile = File.OpenWrite(Path.Combine(file.DstPath, fileName)))
        {
            var bufOffset = blockSizeBytes + 4 + fileNameLength;
            outputFile.Write(decryptedBuffer, bufOffset, decryptedBuffer.Length - bufOffset);

            return new EncryptionResult { OutputFilename = fileName, ProcessedBytes = decryptedBuffer.Length - bufOffset };
        }
    }

    public byte[]? GetNonce(string file)
    {
        if (!File.Exists(file)) return null;
        
        var tempBuf = new byte[OuterMagicHeader.Count + NonceLengthBytes];

        using var inputFile = File.OpenRead(file);
        if (inputFile.Read(tempBuf, 0, OuterMagicHeader.Count + NonceLengthBytes) != OuterMagicHeader.Count + NonceLengthBytes) return null;
        if (OuterMagicHeader.SequenceEqual(tempBuf.Take(OuterMagicHeader.Count)) == false) return null;

        return tempBuf.Skip(OuterMagicHeader.Count).ToArray();
    }
}


public class UnencryptedFile
{
    private readonly IStringHasher _stringHasher;

    public UnencryptedFile(IStringHasher stringHasher, string paddingString)
    {
        _stringHasher = stringHasher;
        _dstName = new Lazy<string>(() => GenerateDstName(paddingString));
    }

    public string SrcPath { get; init; } = "";
    public string SrcName { get; init; } = "";

    public string SrcAbs => Path.Combine(SrcPath, SrcName);


    public string DstPath { get; init; } = "";

    private readonly Lazy<string> _dstName;
    public string DstName => _dstName.Value; 
    private string GenerateDstName(string padding, int levels = 3)
    {
        var encFileName = _stringHasher.HashString(padding + SrcName);

        if (levels == 0)
        {
            return encFileName;
        }
        var sb = new StringBuilder();

        for (var i = 0; i < levels; ++i) 
        {
            sb.Append(encFileName.AsSpan(i*2, 2));
            sb.Append(Path.DirectorySeparatorChar);
        }

        sb.Append(encFileName);

        return sb.ToString();
    }
    
    public bool Skip { get; set; }
}

public class EncryptedFile
{
    public string SrcFile { get; init; } = "";
    public string DstPath { get; init; } = "";
}
