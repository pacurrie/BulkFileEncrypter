using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace BulkFileEncrypter
{
    public class FileSystemSource : IFileSource
    {
        public IEnumerable<string> GetFilesRecursive(string directory)
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