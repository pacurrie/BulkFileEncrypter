using System.CommandLine;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;

namespace BulkFileEncrypter;

public interface ICommands
{
    public int Main(string[] args);
}

public class Commands : ICommands
{
    private readonly IKeyGenerator _keyGen;
    private readonly IFileEncrypter _fileEncrypter;
    private readonly IStringHasher _stringHasher;
    private readonly INonceGenerator _nonceGenerator;

    public Commands(IKeyGenerator keyGen, IFileEncrypter fileEncrypter, IStringHasher stringHasher, INonceGenerator nonceGenerator)
    {
        _keyGen = keyGen;
        _fileEncrypter = fileEncrypter;
        _stringHasher = stringHasher;
        _nonceGenerator = nonceGenerator;
    }

    public int Main(string[] args)
    {
        if (ChaCha20Poly1305.IsSupported == false)
        {
            Console.WriteLine("ChaCha20 with Poly1305 is not supported on this platform.");
        }
        
        
        var rootCommand = new RootCommand
        {
            Description = "Tool for bulk encrypting a directory structure",
            TreatUnmatchedTokensAsErrors = true
        };

        var command = new Command("generate", "Generate encryption key");
        command.SetHandler(GenerateKey);
        rootCommand.AddCommand(command);

        var optVerbose = new Option<bool>(new[] { "/v", "--v", "--verbose" }, () => false, "Verbose output") { Arity = ArgumentArity.Zero };
        rootCommand.AddOption(optVerbose);
        

        command = new Command("encrypt", "Encrypt directory structure");
        var arg1 = new Argument<string>("src", "Unencrypted directory");
        command.AddArgument(arg1);
        var arg2 = new Argument<string>("dst", "Encrypted directory");
        command.AddArgument(arg2);
        var arg3 = new Argument<EncryptionKey>("key", EncryptionKey.Parse, false, "Encryption key");
        command.AddArgument(arg3);
        var opt1 = new Option<bool>(new[]{ "/p", "--p", "--prune"}, () => false, "Prune output directory of files not in source directory") { Arity = ArgumentArity.Zero };
        command.AddOption(opt1);
        var opt2 = new Option<bool>(new[]{ "/f", "--f", "--force"}, () => false, "Force encryption of all files") { Arity = ArgumentArity.Zero };
        command.AddOption(opt2);
        command.SetHandler(Encrypt, arg1, arg2, arg3, opt1, opt2, optVerbose);
        rootCommand.AddCommand(command);

        
        command = new Command("decrypt", "Decrypt directory structure");
        arg1 = new Argument<string>("src", "Encrypted directory");
        command.AddArgument(arg1);
        arg2 = new Argument<string>("dst", "Unencrypted target directory");
        command.AddArgument(arg2);
        arg3 = new Argument<EncryptionKey>("key", EncryptionKey.Parse, false, "Encryption key");
        command.AddArgument(arg3);
        command.SetHandler(Decrypt, arg1, arg2, arg3);
        rootCommand.AddCommand(command);

        return rootCommand.Invoke(args);
    }
    
    private void GenerateKey()
    {
        var key = _keyGen.Generate();
        
        Console.WriteLine("key: " + key.ToBase64());
    }

    private void Encrypt(string src, string dst, EncryptionKey key, bool prune, bool force, bool verbose)
    {
        var srcPath = Path.GetFullPath(src);
        var dstPath = Path.GetFullPath(dst);
        
        if (Directory.Exists(dstPath) == false)
        {
            Directory.CreateDirectory(dstPath);
        }
        
        var knownFiles = new List<UnencryptedFile>();
        foreach (var entry in Directory.GetFiles(srcPath, "*.*", SearchOption.AllDirectories))
        {
            var relPath = Path.GetRelativePath(srcPath, Path.GetDirectoryName(entry)!);
            var relName = relPath == "." ? Path.GetFileName(entry) : Path.Combine(relPath, Path.GetFileName(entry));
            knownFiles.Add(new UnencryptedFile(_stringHasher, key.GetPaddingString()) { SrcPath = srcPath, SrcName = relName, DstPath = dstPath});
        }
        
        var knownFilesByHashedName = knownFiles.ToDictionary(x => Path.GetFileName(x.DstName));
        var directoryCleaner = new DirectoryCleaner(knownFiles.Select(x => x.DstName));
        var pruneList = new List<string>();

        // Recurse output dir
        foreach (var entry in Directory.GetFiles(dstPath, "*.*", SearchOption.AllDirectories))
        {
            var nonce = _fileEncrypter.GetNonce(entry);
            if (nonce != null)
            {
                _nonceGenerator.RegisterNonce(nonce);

                if (knownFilesByHashedName.TryGetValue(Path.GetFileName(entry), out var knownFile))
                {
                    if (!force && File.GetLastWriteTimeUtc(knownFile.SrcAbs) < File.GetLastWriteTimeUtc(entry))
                    {
                        knownFile.Skip = true;
                    }
                }
                else if (prune)
                {
                    pruneList.Add(Path.GetRelativePath(dstPath, entry));
                }
            }
        }

        if (!force) Console.WriteLine($@"Skipping {knownFilesByHashedName.Values.Count(x => x.Skip)} already encrypted files.");

        
        
        // Encrypt files
        PerformOperation(knownFilesByHashedName.Values.Where(x => x.Skip == false),
            x => x.SrcName, 
            x => _fileEncrypter.Encrypt(x, key),
            (x, ts) => $"Encrypted {FormatSpeed(ts, x.ProcessedBytes)}",
            "Encrypted"
        );


        
        
        if (prune)
        {
            Console.WriteLine();

            // Prune encrypted files no longer in source tree
            if (pruneList.Count > 0)
            {
                Console.WriteLine($"Pruning {pruneList.Count} files");
                foreach (var entry in pruneList)
                {
                    File.Delete(Path.Combine(dstPath, entry));
                }
            }

            // Remove empty directories
            var pruneDirs = Directory.GetDirectories(dstPath, "*.*", SearchOption.AllDirectories)
                .Where(x => directoryCleaner.DirectoryShouldBeEmpty(Path.GetRelativePath(dstPath, x)))
                .ToList();

            if (pruneDirs.Count > 0)
            {
                Console.WriteLine($"Pruning {pruneDirs.Count} directories");
                foreach (var dir in pruneDirs.OrderByDescending(x => x.Length))
                {
                    if (Directory.GetDirectories(dir).Length == 0 && Directory.GetFiles(dir).Length == 0)
                    {
                        try
                        {
                            Directory.Delete(dir);
                        }
                        catch
                        {
                            // ignored
                        }
                    }
                }
            }
        }
    }

    private void Decrypt(string src, string dst, EncryptionKey key)
    {
        var srcPath = Path.GetFullPath(src);
        var dstPath = Path.GetFullPath(dst);
        
        if (Directory.Exists(Path.GetFullPath(dstPath)) == false)
        {
            Directory.CreateDirectory(dstPath);
        }

        PerformOperation(Directory.GetFiles(srcPath, "*.*", SearchOption.AllDirectories),
            x => Path.GetFileName(x), 
            x => _fileEncrypter.Decrypt(new EncryptedFile { SrcFile = x, DstPath = dstPath }, key),
            (x, ts) => $"{x.OutputFilename,-64}  ({FormatSpeed(ts, x.ProcessedBytes)})",
            "Decrypted"
            );
    }

    private void PerformOperation<T, TR>(IEnumerable<T> entries, Func<T, string> inputFilenameFormatter, Func<T, TR> operation, Func<TR, TimeSpan, string> successFormatter, string operationName) where TR : EncryptionResult
    {
        var totalTime = TimeSpan.Zero;
        var totalSize = 0L;
        var fileCount = 0;

        foreach (var entry in entries)
        {
            Console.Write(inputFilenameFormatter(entry).PadRight(64));

            var sw = Stopwatch.StartNew();
            var retVal = operation(entry);
            sw.Stop();
            
            string msg;
            if (retVal.Ok)
            {
                msg = successFormatter(retVal, sw.Elapsed);
                totalTime += sw.Elapsed;
                totalSize += retVal.ProcessedBytes;
                fileCount++;
            }
            else
            {
                msg = "Failed";
            }

            Console.WriteLine(" => " + msg);
        }

        if (fileCount > 0)
        {
            Console.WriteLine();
            Console.WriteLine($@"{operationName} {fileCount} files in {FormatSpeed(totalTime, totalSize)}");
        }
    }
    
    
    
    
    
    private static string FormatSpeed(TimeSpan ts, long size)
    {
        double? avgSpeed = null;
        var elapsedSecs = ts.TotalSeconds;

        if (size != 0 && elapsedSecs != 0)
        {
            avgSpeed = size / elapsedSecs;
        }

        return $"{FormatSize(size)} in {ts:mm\\:ss\\.ff}, avg {(avgSpeed.HasValue ? FormatSize(avgSpeed.Value) : "--")}/s";
    }

    private static readonly List<string> SizePostFix = new() { "bytes", "KB", "MB", "GB", "TB" };
    private static string FormatSize(double size)
    {
        var postfix = SizePostFix.First();
        foreach (var pf in SizePostFix.Skip(1))
        {
            if (size < 1024) break;
            size /= 1024;
            postfix = pf;
        }

        return (size < 10 ? Math.Round(size, 2, MidpointRounding.AwayFromZero) : Math.Round(size, 0, MidpointRounding.AwayFromZero)).ToString(CultureInfo.InvariantCulture) + postfix;
    }
}