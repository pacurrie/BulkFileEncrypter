using System;
using System.Collections.Generic;
using System.Diagnostics;
using CommandLine;

namespace BulkFileEncrypter
{
    class TopLevelControlFlow
    {
        public void RunApp(string[] args)
        {
            string invokedCommand = null;
            var options = new Options();

            if (!Parser.Default.ParseArguments(args, options, (command, subOptions) => { invokedCommand = command; }))
            {
                if (Debugger.IsAttached) Console.ReadLine();
                Environment.Exit(Parser.DefaultExitCodeFail);
            }

            switch (invokedCommand)
            {
                case "encrypt":
                    HandleValidation(() => OptionsValidator.Validate(options.Encrypt), () => CommandDispatcher.Encrypt(options.Encrypt));
                    break;
                case "decrypt":
                    HandleValidation(() => OptionsValidator.Validate(options.Decrypt), () => CommandDispatcher.Decrypt(options.Decrypt));
                    break;
                case "generate":
                    HandleValidation(() => null, CommandDispatcher.Generate);
                    break;
                default:
                    Console.WriteLine(options.GetUsage());
                    break;
            }

            if (Debugger.IsAttached) Console.ReadLine();
        }

        private static void HandleValidation(Func<IList<string>> validator, Action onSuccessfullValidation)
        {
            IList<string> errorMessages;
            try
            {
                errorMessages = validator();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error validating arguments: {0}", ex.Message);
                return;
            }

            if (errorMessages != null && errorMessages.Count != 0)
            {
                Console.WriteLine("Error validating arguments:");
                foreach (var error in errorMessages)
                {
                    Console.WriteLine("* {0}", error);
                }
                return;
            }

            try
            {
                onSuccessfullValidation();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error executing command: {0}", ex.Message);
            }
        }
    }
}
