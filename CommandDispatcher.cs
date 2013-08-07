using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace BulkFileEncrypter
{
    public static class CommandDispatcher
    {
        public static void Encrypt(EncryptOptions options)
        {
            PerformCommand(options, "Encryption", () => EncryptCommandHelper.GenerateEncryptionFileList(options), EncryptCommandHelper.PerformEncryption);
            if (options.Prune) EncryptCommandHelper.PruneEncryptedDirectory(options);
        }

        public static void Decrypt(DecryptOptions options)
        {
            PerformCommand(options, "Decryption", () => DirectoryDigger.GetFilesRecursive(options.SourceDir).ToList(), DecryptCommandHelper.PerformDecryption);
        }

        private static void PerformCommand<T>(CommonOptions options, string action, Func<IList<T>> fileList, Func<CommonOptions, T, byte[], long> operation)
        {
            Console.Write("{0} started", action);

            var sw = Stopwatch.StartNew();

            var files = fileList();

            if (files == null || files.Count == 0)
            {
                Console.WriteLine(" (no files found)");
                return;
            }

            Console.WriteLine(options.Verbose ? " (" + files.Count + " files)" : string.Empty);

            var totalSize = files.Sum(o => operation(options, o, options.BinaryKey));

            sw.Stop();

            if (totalSize != 0)
            {
                if (options.Verbose)
                {
                    var avgSpeed = "--";
                    var elapsedSecs = sw.ElapsedMilliseconds/1000;
                    totalSize = totalSize/(1024*1024);

                    if (totalSize != 0 && elapsedSecs != 0)
                    {
                        avgSpeed = (totalSize/elapsedSecs).ToString(CultureInfo.InvariantCulture);
                    }

                    Console.WriteLine("{0} of {1} files complete ({2}MB in {3:hh\\:mm\\:ss}, avg {4}MB/s)", action, files.Count, totalSize, sw.Elapsed, avgSpeed);
                }
                else
                {
                    Console.WriteLine("{0} of {1} files complete", action, files.Count);
                }
            }
        }

        public static void Generate()
        {
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.GenerateKey();
                Console.WriteLine("Generated key: {0}", Convert.ToBase64String(aes.Key));
            }
        }
    }

    public static class EncryptCommandHelper
    {
        public static IList<EncryptOperation> GenerateEncryptionFileList(EncryptOptions options)
        {
            var files = EncryptOperationFactory.Build(options.SourceDir, DirectoryDigger.GetFilesRecursive(options.SourceDir), options.BinaryKey[0], options.Levels).ToList();

            if (!options.Force)
            {
                files = files.Where(x =>
                {
                    var dstFile = Path.Combine(options.DestinationDir, x.EncFileName);
                    if (!File.Exists(dstFile)) return true;

                    var source = File.GetLastWriteTimeUtc(x.FileName);
                    var destination = File.GetLastWriteTimeUtc(dstFile);
                    return source > destination;
                }).ToList();
            }
            return files;
        }

        public static long PerformEncryption(CommonOptions options, EncryptOperation o, byte[] key)
        {
            if (options.Verbose) Console.Write("\t{0} => ", o.RelFileName);
            var result = FileEncrypter.EncryptFile(options.DestinationDir, o, key);
            if (result.HasResult)
            {
                if (options.Verbose) Console.WriteLine(o.EncFileName);
                return result.Result.Item2;
            }
            if (options.Verbose)
            {
                Console.WriteLine("Failed to encrypt file! ({0})", result.ErrorMessage);
            }
            else
            {
                Console.WriteLine("\t{0} => Failed to encrypt file! ({1})", o.RelFileName, result.ErrorMessage);
            }

            return 0;
        }

        public static void PruneEncryptedDirectory(EncryptOptions options)
        {
            if (options.Verbose)
            {
                Console.WriteLine();
                Console.Write("Pruning files");
            }

            int count = 0;
            var validHashes = new HashSet<string>(EncryptOperationFactory.Build(options.SourceDir, DirectoryDigger.GetFilesRecursive(options.SourceDir), options.BinaryKey[0], options.Levels).Select(x => x.EncFileName));
            foreach (var file in Directory.GetFiles(options.DestinationDir))
            {
                var fileName = Path.GetFileName(file);
                if (!string.IsNullOrWhiteSpace(fileName) && !validHashes.Contains(fileName))
                {
                    if (options.Verbose)
                    {
                        if (count == 0) Console.WriteLine();
                        Console.WriteLine("\t{0}", fileName);
                    }
                    File.Delete(file);
                    count++;
                }
            }

            if (options.Verbose) Console.WriteLine(count == 0 ? " (no files found)" : "Pruned " + count + " files");
        }
    }

    public static class DecryptCommandHelper
    {
        public static long PerformDecryption(CommonOptions options, string file, byte[] key)
        {
            if (options.Verbose) Console.Write("{0} => ", file.Replace(options.SourceDir, "").TrimStart(new[] {Path.DirectorySeparatorChar}));
            var result = FileEncrypter.DecryptFile(options.DestinationDir, file, key);
            if (result.HasResult)
            {
                if (options.Verbose) Console.WriteLine(result.Result.Item1.Replace(options.DestinationDir, "").TrimStart(new[] {Path.DirectorySeparatorChar}));
                return result.Result.Item2;
            }
            Console.WriteLine("Failed to decrypt file! ({0})", result.ErrorMessage);
            return 0;
        }
    }
}