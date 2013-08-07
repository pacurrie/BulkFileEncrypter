using System;
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

        private static Assembly LoadEmbeddedDlls(object sender, ResolveEventArgs args)
        {
            if (!args.Name.StartsWith("CommandLine")) return null;

            var currAss = Assembly.GetExecutingAssembly();
            using (var s = currAss.GetManifestResourceStream("BulkFileEncrypter.EmbeddedDlls.CommandLine.dll"))
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