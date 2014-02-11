using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BulkFileEncrypter
{
    public interface IOutputHandler
    {
        void Write(string message);
        void Write(string message, params object[] args);
        void WriteLine();
        void WriteLine(string message);
        void WriteLine(string message, params object[] args);

        void WriteVerbose(string message);
        void WriteVerbose(string message, params object[] args);
        void WriteVerboseLine();
        void WriteVerboseLine(string message);
        void WriteVerboseLine(string message, params object[] args);

        void WriteVerboseOrNormalLine(string message, string verboseMessage);
        void WriteVerboseOrNormalLine(string message, string verboseMessage, params object[] combinedArgs);
    }
}
