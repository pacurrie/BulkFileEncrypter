using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BulkFileEncrypter
{
    class StdOutHandler : IOutputHandler
    {
        private bool isVerbose;

        public StdOutHandler(bool verbose)
        {
            isVerbose = verbose;
        }

        public void Write(string message)
        {
            Console.Write(message);
        }

        public void Write(string message, params object[] args)
        {
            Console.Write(message, args);
        }

        public void WriteLine()
        {
            Console.WriteLine();
        }

        public void WriteLine(string message)
        {
            Console.WriteLine(message);
        }

        public void WriteLine(string message, params object[] args)
        {
            Console.WriteLine(message, args);
        }


        public void WriteVerbose(string message)
        {
            if (isVerbose)
            {
                Console.Write(message);
            }
        }

        public void WriteVerbose(string message, params object[] args)
        {
            if (isVerbose)
            {
                Console.Write(message, args);
            }
        }

        public void WriteVerboseLine()
        {
            if (isVerbose)
            {
                Console.WriteLine();
            }
        }

        public void WriteVerboseLine(string message)
        {
            if (isVerbose)
            {
                Console.WriteLine(message);
            }
        }

        public void WriteVerboseLine(string message, params object[] args)
        {
            if (isVerbose)
            {
                Console.WriteLine(message, args);
            }
        }

        public void WriteVerboseOrNormalLine(string message, string verboseMessage)
        {
            Console.WriteLine(isVerbose ? verboseMessage : message);
        }

        public void WriteVerboseOrNormalLine(string message, string verboseMessage, params object[] combinedArgs)
        {
            Console.WriteLine(isVerbose ? verboseMessage : message, combinedArgs);
        }
    }
}
