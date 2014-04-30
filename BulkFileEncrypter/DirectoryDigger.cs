using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace BulkFileEncrypter
{
    public static class DirectoryDigger
    {
        public static IEnumerable<string> GetFilesRecursive(string directory)
        {
            foreach (var f in Directory.EnumerateFiles(directory))
            {
                yield return f;
            }

            foreach (var f in Directory.EnumerateDirectories(directory).SelectMany(GetFilesRecursive))
            {
                yield return f;
            }
        }
    }
}
