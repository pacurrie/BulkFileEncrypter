using Microsoft.Extensions.DependencyInjection;

namespace BulkFileEncrypter
{
    internal class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            var serviceProvider = new ServiceCollection()
                .AddSingleton<IRandomGenerator, RandomGenerator>()
                .AddSingleton<IStringHasher, StringHasher>()
                .AddTransient<IKeyGenerator, KeyGenerator>()
                .AddSingleton<INonceGenerator, NonceGenerator>()
                .AddSingleton<IFileEncrypter, FileEncrypter>()
                .AddTransient<ICommands, Commands>()
                .BuildServiceProvider();
            
            using var scope = serviceProvider.CreateScope();
            return serviceProvider.GetService<ICommands>()!.Main(args);
        }
    }
}





