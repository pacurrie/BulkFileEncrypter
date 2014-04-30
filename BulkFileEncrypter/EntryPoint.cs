using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace BulkFileEncrypter
{
    class EntryPoint
    {
        [STAThread]
        private static void Main(string[] args)
        {
            AppDomain.CurrentDomain.AssemblyResolve += LoadEmbeddedDlls;

            new TopLevelControlFlow().RunApp(args);
        }

        private static List<string> embeddedDlls = new List<string> { "CommandLine.dll", "Security.Cryptography.dll" };

        private static Assembly LoadEmbeddedDlls(object sender, ResolveEventArgs args)
        {
            var name = args.Name.Split(new[] { ',' })[0];

            if (!embeddedDlls.Any(x => x.Contains(name))) {return null;}

            var requestedAssembly = "BulkFileEncrypter.EmbeddedDlls." + name + ".dll";

            var currAss = Assembly.GetExecutingAssembly();
            using (var s = currAss.GetManifestResourceStream(requestedAssembly))
            {
                if (s != null)
                {
                    var buf = new byte[s.Length];
                    s.Read(buf, 0, buf.Length);
                    return Assembly.Load(buf);
                }
            }
            return null;
        }
    }
}
