using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Security.Cryptography;

namespace BulkFileEncrypter
{
    public static class FileEncrypter
    {
        private static readonly List<byte> OuterMagicHeader = new List<byte> {0x2f, 0x56, 0xd1, 0xf2, 0x3d, 0x2e, 0x4e, 0x65, 0xaf, 0xf7, 0x06, 0x72, 0x16, 0x91, 0x2a, 0x7d};
        private static readonly List<byte> MagicHeader = new List<byte> {0x62, 0xdb, 0x04, 0xaf};

        private const int KeyLength = 256;
        public const int KeyLengthInBytes = KeyLength / 8;

        private static readonly int TagStartPos = OuterMagicHeader.Count + sizeof(Int32) + sizeof(Int32);

        public enum ErrorType
        {
            NoError = 0,
            FileNoExist = 1,
            OutDirMissing = 2,
            MagicBytesMismatch = 3,
            NotAnEncryptedFile = 4,
            CorruptFile = 5,
            IncorrectKey = 6,
            FailedChecksum = 7
        };

        private static readonly Dictionary<ErrorType, Some<Tuple<string, long>>> ErrorValues = new Dictionary<ErrorType, Some<Tuple<string, long>>>
        {
            {ErrorType.NoError, new Some<Tuple<string, long>>((int) ErrorType.NoError, "No error")},
            {ErrorType.FileNoExist, new Some<Tuple<string, long>>((int) ErrorType.FileNoExist, "File does not exist")},
            {ErrorType.OutDirMissing, new Some<Tuple<string, long>>((int) ErrorType.OutDirMissing, "No output directory")},
            {ErrorType.MagicBytesMismatch, new Some<Tuple<string, long>>((int) ErrorType.MagicBytesMismatch, "File is not an encrypted file")},
            {ErrorType.NotAnEncryptedFile, new Some<Tuple<string, long>>((int) ErrorType.NotAnEncryptedFile, "File is not an encrypted file")},
            {ErrorType.CorruptFile, new Some<Tuple<string, long>>((int) ErrorType.CorruptFile, "File is corrupt or incorrect key specified")},
            {ErrorType.IncorrectKey, new Some<Tuple<string, long>>((int) ErrorType.IncorrectKey, "Incorrect key specified")},
            {ErrorType.FailedChecksum, new Some<Tuple<string, long>>((int) ErrorType.IncorrectKey, "File failed checksum validation")},
        };

        public static byte[] GenerateKey()
        {
            using (var aes = new AuthenticatedAesCng())
            {
                aes.CngMode = CngChainingMode.Gcm;
                aes.GenerateKey();
                return aes.Key;
            }
        }


        public static Some<Tuple<string, long>> EncryptFile(string dstDir, EncryptOperation oper, byte[] key)
        {
            if (!File.Exists(oper.FileName)) return ErrorValues[ErrorType.FileNoExist];

            var outputFileName = Path.Combine(dstDir, oper.EncFileName);
            var outputDir = Path.GetDirectoryName(outputFileName);
            if (string.IsNullOrWhiteSpace(outputDir)) return ErrorValues[ErrorType.OutDirMissing];
            Directory.CreateDirectory(outputDir);

            using (var aes = new AuthenticatedAesCng())
            {
                aes.CngMode = CngChainingMode.Gcm;
                aes.Key = key;
                aes.GenerateIV();

                byte[] tag;

                using (var outputFile = File.OpenWrite(outputFileName))
                {
                    outputFile.Write(OuterMagicHeader.ToArray());
                    outputFile.Write(BitConverter.GetBytes(aes.Tag.Length));
                    outputFile.Write(BitConverter.GetBytes(aes.IV.Length));
                    outputFile.Write(aes.Tag);
                    outputFile.Write(aes.IV);

                    using (var enc = aes.CreateEncryptor())
                    {
                        using (var cryptoStream = new CryptoStream(outputFile, enc, CryptoStreamMode.Write))
                        {
                            cryptoStream.Write(MagicHeader.ToArray());
                            var fileName = Encoding.UTF8.GetBytes(oper.RelFileName);
                            var fileNameSize = BitConverter.GetBytes(Convert.ToInt32(fileName.Length));
                            cryptoStream.Write(fileNameSize);
                            cryptoStream.Write(fileName);

                            using (var inputFile = File.OpenRead(oper.FileName))
                            {
                                inputFile.CopyTo(cryptoStream);
                            }
                        }

                        tag = ((IAuthenticatedCryptoTransform)enc).GetTag();
                    }
                }

                using (var outputFile = File.OpenWrite(outputFileName))
                {
                    outputFile.Seek(TagStartPos, SeekOrigin.Begin);
                    outputFile.Write(tag, 0, tag.Length);
                }

                return new Some<Tuple<string, long>>(Tuple.Create(outputFileName, new FileInfo(oper.FileName).Length));
            }
        }

        public static Some<Tuple<string, long>> DecryptFile(string dstDir, string filename, byte[] key)
        {
            if (!File.Exists(filename)) return ErrorValues[ErrorType.FileNoExist];

            using (var inputFile = File.OpenRead(filename))
            {
                var outerBuffer = new byte[TagStartPos];
                if (inputFile.Read(outerBuffer, 0, outerBuffer.Length) != outerBuffer.Length)
                {
                    return ErrorValues[ErrorType.NotAnEncryptedFile];
                }

                if (!outerBuffer.Take(OuterMagicHeader.Count).SequenceEqual(OuterMagicHeader))
                {
                    return ErrorValues[ErrorType.MagicBytesMismatch];
                }

                var tagLength = BitConverter.ToInt32(outerBuffer, OuterMagicHeader.Count);
                var ivLength = BitConverter.ToInt32(outerBuffer, OuterMagicHeader.Count + sizeof(Int32));

                using (var aes = new AuthenticatedAesCng())
                {
                    outerBuffer = new byte[tagLength + ivLength];
                    if (inputFile.Read(outerBuffer, 0, outerBuffer.Length) != outerBuffer.Length)
                    {
                        return ErrorValues[ErrorType.NotAnEncryptedFile];
                    }

                    aes.CngMode = CngChainingMode.Gcm;
                    aes.Key = key;
                    aes.Tag = outerBuffer.Take(tagLength).ToArray();
                    aes.IV = outerBuffer.Skip(tagLength).Take(ivLength).ToArray();

                    using (var dec = aes.CreateDecryptor())
                    using (var cryptoStream = new CryptoStream(inputFile, dec, CryptoStreamMode.Read))
                    {
                        var buf = new byte[MagicHeader.Count + sizeof(Int32)];
                        if (cryptoStream.Read(buf, 0, buf.Length) != buf.Length)
                        {
                            return ErrorValues[ErrorType.CorruptFile];
                        }

                        if (!buf.Take(MagicHeader.Count).SequenceEqual(MagicHeader))
                        {
                            return ErrorValues[ErrorType.MagicBytesMismatch];
                        }

                        var nameLength = BitConverter.ToInt32(buf, MagicHeader.Count);
                        buf = new byte[nameLength];
                        if (cryptoStream.Read(buf, 0, buf.Length) != buf.Length)
                        {
                            return ErrorValues[ErrorType.CorruptFile];
                        }
                        var fileName = Encoding.UTF8.GetString(buf, 0, buf.Length);

                        var outputFileName = Path.Combine(dstDir, fileName);
                        var outputDir = Path.GetDirectoryName(outputFileName);

                        if (string.IsNullOrWhiteSpace(outputDir)) return ErrorValues[ErrorType.OutDirMissing];
                        Directory.CreateDirectory(outputDir);

                        try
                        {
                            using (var outputFile = File.OpenWrite(outputFileName))
                            {
                                cryptoStream.CopyTo(outputFile);
                            }
                        }
                        catch (CryptographicException)
                        {
                            File.Delete(outputFileName);
                            return ErrorValues[ErrorType.FailedChecksum];
                        }

                        return new Some<Tuple<string, long>>(Tuple.Create(outputFileName, new FileInfo(outputFileName).Length));
                    }
                }
            }
        }
    }
}