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
        public static void Encrypt(EncryptOptions options, IOutputHandler outputHandler)
        {
            PerformCommand(options, outputHandler, "Encryption", () => EncryptCommandHelper.GenerateEncryptionFileList(options), EncryptCommandHelper.PerformEncryption);
            if (options.Prune) EncryptCommandHelper.PruneEncryptedDirectory(options, outputHandler);
        }

        public static void Decrypt(DecryptOptions options, IOutputHandler outputHandler)
        {
            PerformCommand(options, outputHandler, "Decryption", () => DirectoryDigger.GetFilesRecursive(options.SourceDir).ToList(), DecryptCommandHelper.PerformDecryption);
        }

        private static void PerformCommand<T>(CommonOptions options, IOutputHandler outputHandler, string action, Func<IList<T>> fileList, Func<CommonOptions, IOutputHandler, T, byte[], long> operation)
        {
            outputHandler.Write("{0} started", action);

            var sw = Stopwatch.StartNew();

            var files = fileList();
            if (files == null || files.Count == 0)
            {
                outputHandler.WriteLine(" (no files found)");
                return;
            }

            outputHandler.WriteVerboseOrNormalLine("", " ({0} files)", files.Count);
            var totalSize = files.Sum(o => operation(options, outputHandler, o, options.BinaryKey));

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

                    outputHandler.WriteVerboseLine("{0} of {1} files complete ({2}MB in {3:hh\\:mm\\:ss}, avg {4}MB/s)", action, files.Count, totalSize, sw.Elapsed, avgSpeed);
                }
                else
                {
                    outputHandler.WriteLine("{0} of {1} files complete", action, files.Count);
                }
            }
        }

        public static void Generate(IOutputHandler outputHandler)
        {
            var key = FileEncrypter.GenerateKey();
            outputHandler.WriteLine("Generated key: {0}", Convert.ToBase64String(key));
        }
    }

    public static class EncryptCommandHelper
    {
        public static IList<EncryptOperation> GenerateEncryptionFileList(EncryptOptions options)
        {
            var fileNames = DirectoryDigger.GetFilesRecursive(options.SourceDir).Where(x => string.IsNullOrWhiteSpace(options.IgnoreFilePath) || !x.Contains(options.IgnoreFilePath));
            var files = EncryptOperationFactory.Build(options.SourceDir, fileNames, options.BinaryKey[0], options.Levels).ToList();

            if (!options.Force)
            {
                files = files.Where(x => IsSourceFileNewer(x.FileName, Path.Combine(options.DestinationDir, x.EncFileName))).ToList();
            }
            return files;
        }

        private static bool IsSourceFileNewer(string sourceFileName, string destinationFileName)
        {
            if (!File.Exists(destinationFileName))
            {
                return true;
            }


            return File.GetLastWriteTimeUtc(sourceFileName) > File.GetLastWriteTimeUtc(destinationFileName);
        }

        public static long PerformEncryption(CommonOptions options, IOutputHandler outputHandler, EncryptOperation o, byte[] key)
        {
            outputHandler.WriteVerbose("\t{0} => ", o.RelFileName);

            var result = FileEncrypter.EncryptFile(options.DestinationDir, o, key);
            if (result.HasResult)
            {
                outputHandler.WriteVerboseLine(o.EncFileName);
                return result.Result.Item2;
            }

            outputHandler.WriteVerboseOrNormalLine("\t{0} => Failed to encrypt file! ({1})", "Failed to encrypt file! ({1})", o.RelFileName, result.ErrorMessage);
            return 0;
        }

        public static void PruneEncryptedDirectory(EncryptOptions options, IOutputHandler outputHandler)
        {
            outputHandler.WriteVerboseLine();
            outputHandler.WriteVerbose("Pruning files");

            int count = 0;
            var fileNames = DirectoryDigger.GetFilesRecursive(options.SourceDir).Where(x => string.IsNullOrWhiteSpace(options.IgnoreFilePath) || !x.Contains(options.IgnoreFilePath));
            var validFiles = EncryptOperationFactory.Build(options.SourceDir, fileNames, options.BinaryKey[0], options.Levels).Select(x => x.EncFileName);
            var validHashes = new HashSet<string>(validFiles.Select(Path.GetFileName));
            foreach (var file in DirectoryDigger.GetFilesRecursive(options.DestinationDir))
            {
                var fileName = Path.GetFileName(file);
                if (!string.IsNullOrWhiteSpace(fileName) && !validHashes.Contains(fileName))
                {
                    if (count == 0)
                    {
                        outputHandler.WriteVerboseLine();
                    }
                    outputHandler.WriteVerboseLine("\t{0}", fileName);
                    File.Delete(file);
                    count++;
                }
            }

            outputHandler.WriteVerboseLine(count == 0 ? " (no files found)" : "Pruned " + count + " files");
        }
    }

    public static class DecryptCommandHelper
    {
        public static long PerformDecryption(CommonOptions options, IOutputHandler outputHandler, string file, byte[] key)
        {
            outputHandler.WriteVerbose("{0} => ", file.Replace(options.SourceDir, "").TrimStart(new[] { Path.DirectorySeparatorChar }));

            var result = FileEncrypter.DecryptFile(options.DestinationDir, file, key);
            if (result.HasResult)
            {
                outputHandler.WriteVerboseLine(result.Result.Item1.Replace(options.DestinationDir, "").TrimStart(new[] { Path.DirectorySeparatorChar }));
                return result.Result.Item2;
            }

            outputHandler.WriteLine("Failed to decrypt file! ({0})", result.ErrorMessage);
            return 0;
        }
    }
}