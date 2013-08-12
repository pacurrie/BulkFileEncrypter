using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace BulkFileEncrypter
{
    public class Hashing
    {
        public static byte[] HashString(string input)
        {
            using (var hasher = new SHA256Cng())
            {
                return hasher.ComputeHash(Encoding.UTF8.GetBytes(input));
            }
        }
    }
}
