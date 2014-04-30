using System;
using System.Collections.Generic;
using System.IO;
using CommandLine;
using CommandLine.Text;

namespace BulkFileEncrypter
{
    public static class OptionsValidator
    {
        public static IList<string> Validate(EncryptOptions options)
        {
            var retVal = new List<string>();

            if (options.Levels < 0 || options.Levels > 5)
            {
                retVal.Add("Directory level is outside valid range (0-5)");
            }

            retVal.AddRange(Validate(options as CommonOptions));
            return retVal;
        }

        public static IList<string> Validate(DecryptOptions options)
        {
            return Validate(options as CommonOptions);
        }

        private static IList<string> Validate(CommonOptions options)
        {
            var retVal = new List<string>();

            if (options.BinaryKey.Length != FileEncrypter.KeyLengthInBytes)
            {
                retVal.Add("Invalid key length.");
            }

            if (!Directory.Exists(options.SourceDir))
            {
                retVal.Add("Source directory does not exist.");
            }

            var fullSrc = Path.GetFullPath(options.SourceDir);
            var fullDst = Path.GetFullPath(options.DestinationDir);

            if (fullDst.StartsWith(fullSrc))
            {
                retVal.Add("Destination directory cannot be located inside source directory.");
            }

            return retVal;
        }

        public static List<string> Validate(bool options)
        {
            return null;
        }
    }


    public class Options
    {
        [VerbOption("encrypt", HelpText = "Encrypt a directory structure")]
        public EncryptOptions Encrypt { get; set; }

        [VerbOption("decrypt", HelpText = "Decrypt a directory structure")]
        public DecryptOptions Decrypt { get; set; }

        [VerbOption("generate", HelpText = "Generates an encryption key")]
        public bool Generate { get; set; }

        [ParserState]
        public IParserState LastParserState { get; set; }

        [HelpOption]
        public string GetUsage()
        {
            return HelpText.AutoBuild(this, current => HelpText.DefaultParsingErrorsHandler(this, current));
        }

        [HelpVerbOption]
        public string GetUsage(string verb)
        {
            return HelpText.AutoBuild(this, verb);
        }
    }

    public class EncryptOptions : CommonOptions
    {
        [Option('p', "prune", DefaultValue = true, HelpText = "Remove files in output directory which do not have a corresponding file in the input directory")]
        public bool Prune { get; set; }

        [Option('f', "force", DefaultValue = false, HelpText = "Force processing of all files")]
        public bool Force { get; set; }

        [Option('l', "levels", Required = false, DefaultValue = 2, HelpText = "How many levels to use in the destination directory")]
        public int Levels { get; set; }

        [Option('i', "ignore", Required = false, HelpText = "Filepath to ignore")]
        public string IgnoreFilePath { get; set; }
    }

    public class DecryptOptions : CommonOptions
    {
    }

    public class CommonOptions
    {
        [Option('k', "key", Required = true, HelpText = "Encryption key to use (base64 encoded)")]
        public string Key { get; set; }

        [Option('s', "src", Required = true, HelpText = "Source directory")]
        public string SourceDir { get; set; }

        [Option('d', "dst", Required = true, HelpText = "Destination directory")]
        public string DestinationDir { get; set; }

        [Option('v', "verbose", Required = false, DefaultValue = false, HelpText = "Verbose output")]
        public bool Verbose { get; set; }

        public byte[] BinaryKey { get { return Convert.FromBase64String(Key); } }
    }
}
