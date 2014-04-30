using System.Collections.Generic;

namespace BulkFileEncrypter
{
    public interface IFileSource
    {
        IEnumerable<string> GetFilesRecursive(string directory);
    }
}
