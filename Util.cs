using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace BulkFileEncrypter
{
    public static class Util
    {
        public static byte[] HashString(string input)
        {
            using (var hasher = new SHA256Managed())
            {
                return hasher.ComputeHash(Encoding.UTF8.GetBytes(input));
            }
        }

        public static string HexDump(byte[] input)
        {
            return BitConverter.ToString(input).Replace("-", String.Empty);
        }

        public static void Write(this Stream stream, byte[] buffer)
        {
            stream.Write(buffer, 0, buffer.Length);
        }
    }

    public class Some<T>
    {
        public T Result { get; private set; }
        public bool HasResult { get; private set; }
        public int ErrorCode { get; private set; }
        public string ErrorMessage { get; private set; }

        public const int NoErrorCodeGiven = -1;
        public const int NoError = 0;

        public Some(T result)
        {
            Result = result;
            HasResult = true;
        }

        public Some()
        {
            HasResult = false;
            ErrorCode = NoErrorCodeGiven;
        }

        public Some(int errorCode, string errorMessage)
        {
            HasResult = false;
            ErrorCode = errorCode;
            ErrorMessage = errorMessage;
        }
    }
}
