using System;
using System.IO;
using System.Windows;

namespace PasswordServiceWpf;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        if (e.Args.Length >= 3 && e.Args[0] == "--selftest")
        {
            var path = e.Args[1];
            var master = e.Args[2];
            var records = VaultCore.LoadVault(path, master);
            var outPath = path + ".cs.enc";
            VaultCore.SaveVault(outPath, master, records);
            Environment.Exit(0);
            return;
        }

        base.OnStartup(e);

        string vaultPath;
        bool unavailable = false;
        bool firstRun = false;
        try
        {
            var (loadedPath, configured) = VaultSettings.LoadVaultLocation();
            vaultPath = loadedPath;
            if (!configured)
                firstRun = true;
            else if (!File.Exists(vaultPath))
                unavailable = true;
        }
        catch (InvalidDataException)
        {
            vaultPath = VaultSettings.DefaultVaultFile;
            unavailable = true;
        }

        var unlockWin = new UnlockWindow(vaultPath, unavailable, firstRun);
        MainWindow = unlockWin;
        unlockWin.Show();
    }
}
