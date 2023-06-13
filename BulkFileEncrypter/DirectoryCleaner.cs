namespace BulkFileEncrypter;

public class DirectoryCleaner
{
    private readonly HashSet<string> _expectedDirectories = new();

    public DirectoryCleaner(IEnumerable<string?> paths)
    {
        foreach (var path in paths)
        {
            var p = path;
            while (!string.IsNullOrWhiteSpace(p))
            {
                AddExpectedDirectory(p);
                p = Path.GetDirectoryName(p);
            }
        }
    }
    
    private void AddExpectedDirectory(string? path)
    {
        var dirPath = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(dirPath))
        {
            _expectedDirectories.Add(dirPath);
        }
    }

    public bool DirectoryShouldBeEmpty(string path)
    {
        return !_expectedDirectories.Contains(path);
    }
}