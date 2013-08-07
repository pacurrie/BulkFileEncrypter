using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace BulkFileEncrypter
{
    public class EncryptOperation
    {
        public string FileName { get; set; }
        public string RelFileName { get; set; }
        public string EncFileName { get; set; }
    }

    public static class EncryptOperationFactory
    {
        public static IEnumerable<EncryptOperation> Build(string baseDir, IEnumerable<string> files, byte paddingByte, int levels)
        {
            var fullBasePath = Path.GetFullPath(baseDir);
            var paddingString = BitConverter.ToString(new[] { paddingByte });

            return files.Select(Path.GetFullPath)
                .Select(x => new { f = x, rf = x.Replace(fullBasePath, string.Empty).TrimStart(new[] { Path.DirectorySeparatorChar }) })
                .Select(x => new EncryptOperation { FileName = x.f, RelFileName = x.rf, EncFileName = GenerateEncryptedFileName(paddingString, x.rf, levels) });
        }

        private static string GenerateEncryptedFileName(string padding, string fileName, int levels)
        {
            var encFileName = Util.HexDump(Util.HashString(padding + fileName));

            if (levels == 0)
            { 
                return encFileName;
            }

            var sb = new StringBuilder();

            for (int i = 0; i < levels; ++i) 
            {
                sb.Append(encFileName.Substring(i*2, 2));
                sb.Append(Path.DirectorySeparatorChar);
            }

            sb.Append(encFileName);

            return sb.ToString();
        }
    }
}