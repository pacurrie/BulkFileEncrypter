using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace BulkFileEncrypter
{
    public static class FileEncrypter
    {
        private static readonly List<byte> OuterMagicHeader = new List<byte> {0x2f, 0x56, 0xd1, 0xf2, 0x3d, 0xe2, 0x4e, 0x65, 0xaf, 0xf7, 0x06, 0x72, 0x16, 0x91, 0x2a, 0x7d};
        private static readonly List<byte> MagicHeader = new List<byte> {0x62, 0xbd, 0x04, 0xaf};
        private const int BufSize = 1*1024*1024;

        private const int KeyLength = 256;
        public const int KeyLengthInBytes = KeyLength / 8;
        private const int IvLength = 128;
        private const int IvLengthInBytes = IvLength / 8;

        public enum ErrorType
        {
            NoError = 0,
            FileNoExist = 1,
            OutDirMissing = 2,
            MagicBytesMismatch = 3,
            NotAnEncryptedFile = 4,
            CorruptFile = 5,
            IncorrectKey = 6
        };

        private static readonly Dictionary<ErrorType, Some<Tuple<string, long>>> ErrorValues = new Dictionary<ErrorType, Some<Tuple<string, long>>>
        {
            {ErrorType.NoError, new Some<Tuple<string, long>>((int) ErrorType.NoError, "No error")},
            {ErrorType.FileNoExist, new Some<Tuple<string, long>>((int) ErrorType.FileNoExist, "File does not exist")},
            {ErrorType.OutDirMissing, new Some<Tuple<string, long>>((int) ErrorType.OutDirMissing, "No output directory")},
            {ErrorType.MagicBytesMismatch, new Some<Tuple<string, long>>((int) ErrorType.MagicBytesMismatch, "File is not an encrypted file")},
            {ErrorType.NotAnEncryptedFile, new Some<Tuple<string, long>>((int) ErrorType.NotAnEncryptedFile, "File is not an encrtpyed file")},
            {ErrorType.CorruptFile, new Some<Tuple<string, long>>((int) ErrorType.CorruptFile, "File is corrupt or incorrect key specified")},
            {ErrorType.IncorrectKey, new Some<Tuple<string, long>>((int) ErrorType.IncorrectKey, "Incorrect key specified")},
        };


        public static Some<Tuple<string, long>> EncryptFile(string dstDir, EncryptOperation oper, byte[] key)
        {
            if (!File.Exists(oper.FileName)) return ErrorValues[ErrorType.FileNoExist];

            var outputFileName = Path.Combine(dstDir, oper.EncFileName);
            var outputDir = Path.GetDirectoryName(outputFileName);
            if (string.IsNullOrWhiteSpace(outputDir)) return ErrorValues[ErrorType.OutDirMissing];
            Directory.CreateDirectory(outputDir);

            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Key = key;
                aes.GenerateIV();

                using (var enc = aes.CreateEncryptor())
                {
                    var inBuf = new byte[BufSize];
                    var outBuf = new byte[BufSize];
                    using (var outputFile = File.OpenWrite(outputFileName))
                    {
                        outputFile.Write(OuterMagicHeader.ToArray());
                        outputFile.Write(aes.IV);

                        var header = CreateHeader(oper.RelFileName);
                        header.CopyTo(inBuf, 0);

                        using (var inputFile = File.OpenRead(oper.FileName))
                        {
                            int bytesInBuffer = inputFile.Read(inBuf, header.Length, inBuf.Length - header.Length) + header.Length;
                            long totalInputBytes = 0;
                            do
                            {
                                if (bytesInBuffer == inBuf.Length)
                                {
                                    var validBytes = enc.TransformBlock(inBuf, 0, inBuf.Length, outBuf, 0);
                                    outputFile.Write(outBuf, 0, validBytes);
                                }
                                else
                                {
                                    var finalBuf = enc.TransformFinalBlock(inBuf, 0, bytesInBuffer);
                                    outputFile.Write(finalBuf);
                                }
                                totalInputBytes += bytesInBuffer;
                            } while ((bytesInBuffer = inputFile.Read(inBuf, 0, BufSize)) != 0);

                            return new Some<Tuple<string, long>>(Tuple.Create(outputFileName, totalInputBytes));
                        }
                    }
                }
            }
        }

        public static Some<Tuple<string, long>> DecryptFile(string dstDir, string filename, byte[] key)
        {
            if (!File.Exists(filename)) return ErrorValues[ErrorType.FileNoExist];

            using (var inputFile = File.OpenRead(filename))
            {
                var outerBuffer = new byte[OuterMagicHeader.Count + IvLengthInBytes];
                if (inputFile.Read(outerBuffer, 0, outerBuffer.Length) != outerBuffer.Length)
                {
                    return ErrorValues[ErrorType.NotAnEncryptedFile];
                }

                if (!outerBuffer.Take(OuterMagicHeader.Count).SequenceEqual(OuterMagicHeader))
                {
                    return ErrorValues[ErrorType.MagicBytesMismatch];
                }

                using (var aes = new AesCryptoServiceProvider())
                {
                    aes.Key = key;
                    aes.IV = outerBuffer.Skip(OuterMagicHeader.Count).Take(IvLengthInBytes).ToArray();
                    using (var dec = aes.CreateDecryptor())
                    {
                        var inBuf = new byte[BufSize];
                        var outBuf = new byte[BufSize];

                        var bytesInBuffer = inputFile.Read(inBuf, 0, inBuf.Length);

                        byte[] validBuf;
                        try
                        {
                            validBuf = DecryptBuffer(dec, inBuf, bytesInBuffer, outBuf);
                        }
                        catch (CryptographicException)
                        {
                            return ErrorValues[ErrorType.IncorrectKey];
                        }

                        if (! validBuf.Take(MagicHeader.Count).SequenceEqual(MagicHeader))
                        {
                            return ErrorValues[ErrorType.CorruptFile];
                        }

                        int current = MagicHeader.Count;
                        var nameLength = BitConverter.ToInt32(validBuf, current);
                        current += sizeof (Int32);
                        var fileName = Encoding.UTF8.GetString(validBuf, current, nameLength);
                        current += nameLength;

                        var outputFileName = Path.Combine(dstDir, fileName);
                        var outputDir = Path.GetDirectoryName(outputFileName);

                        if (string.IsNullOrWhiteSpace(outputDir)) return ErrorValues[ErrorType.OutDirMissing];
                        Directory.CreateDirectory(outputDir);

                        using (var outputFile = File.OpenWrite(outputFileName))
                        {
                            outputFile.Write(validBuf, current, validBuf.Length - current);
                            long totalOutputBytes = validBuf.Length - current;

                            while ((bytesInBuffer = inputFile.Read(inBuf, 0, inBuf.Length)) != 0)
                            {
                                var decBuf = DecryptBuffer(dec, inBuf, bytesInBuffer, outBuf);
                                outputFile.Write(decBuf);
                                totalOutputBytes += decBuf.Length;
                            }
                            return new Some<Tuple<string, long>>(Tuple.Create(outputFileName, totalOutputBytes));
                        }
                    }
                }
            }
        }

        private static byte[] DecryptBuffer(ICryptoTransform dec, byte[] inBuf, int count, byte[] outBuf)
        {
            if (count != inBuf.Length)
            {
                return dec.TransformFinalBlock(inBuf, 0, count);
            }

            var validBytes = dec.TransformBlock(inBuf, 0, inBuf.Length, outBuf, 0);
            if (validBytes == outBuf.Length)
            {
                return outBuf;
            }

            var truncatedArray = new byte[validBytes];
            Array.Copy(outBuf, truncatedArray, validBytes);
            return truncatedArray;
        }

        private static byte[] CreateHeader(string relSourceName)
        {
            var retVal = new List<byte>(MagicHeader);
            var fileNameBytes = Encoding.UTF8.GetBytes(relSourceName);
            retVal.AddRange(BitConverter.GetBytes(Convert.ToInt32(fileNameBytes.Length)));
            retVal.AddRange(fileNameBytes);
            return retVal.ToArray();
        }
    }
}