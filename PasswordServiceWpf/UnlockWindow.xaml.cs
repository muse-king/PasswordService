using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;

namespace PasswordServiceWpf;

public partial class UnlockWindow : Window
{
    private string _vaultPath;
    private bool _unavailable;
    private bool _firstRun;
    private bool _persistLocation;
    private bool _isSetup;

    public UnlockWindow(string vaultPath, bool unavailable = false, bool firstRun = false)
    {
        InitializeComponent();
        _vaultPath = vaultPath;
        _unavailable = unavailable;
        _firstRun = firstRun;
        SourceInitialized += (_, _) => ApplyDarkTitleBar(this);
        Loaded += (_, _) => RefreshMode();
    }

    internal static void ApplyDarkTitleBar(Window window)
    {
        try
        {
            var hwnd = new WindowInteropHelper(window).Handle;
            if (hwnd == IntPtr.Zero) return;
            int dark = 1;
            DwmSetWindowAttribute(hwnd, 20, ref dark, sizeof(int));
        }
        catch { }
    }

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

    private void RefreshMode()
    {
        FirstRunPanel.Visibility = Visibility.Collapsed;
        UnavailablePanel.Visibility = Visibility.Collapsed;
        CardPanel.Visibility = Visibility.Collapsed;

        if (_firstRun)
        {
            TitleText.Text = "选择密码库位置";
            FirstRunPanel.Visibility = Visibility.Visible;
            StatusText.Text = "";
            return;
        }

        if (_unavailable)
        {
            TitleText.Text = "密码库位置不可用";
            UnavailablePanel.Visibility = Visibility.Visible;
            StatusText.Text = "";
            return;
        }

        CardPanel.Visibility = Visibility.Visible;
        bool exists = File.Exists(_vaultPath);
        _isSetup = !exists;
        TitleText.Text = _isSetup ? "设置总密码" : "输入总密码";
        ConfirmPanel.Visibility = _isSetup ? Visibility.Visible : Visibility.Collapsed;
        ActionBtn.Content = _isSetup ? "创建密码库" : "解锁";
        StatusText.Text = "";
        PasswordInput.Focus();
    }

    private void ChooseLocation_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog { Title = "选择密码库文件夹" };
        if (dialog.ShowDialog(this) != true) return;

        _vaultPath = Path.Combine(dialog.FolderName, "passwords.enc");
        _unavailable = false;
        _firstRun = false;
        _persistLocation = true;
        if (File.Exists(_vaultPath))
        {
            try { VaultSettings.SaveVaultLocation(dialog.FolderName); } catch { }
        }
        RefreshMode();
    }

    private void UseDefaultLocation_Click(object sender, RoutedEventArgs e)
    {
        _vaultPath = VaultSettings.DefaultVaultFile;
        _unavailable = false;
        _firstRun = false;
        _persistLocation = true;
        if (File.Exists(_vaultPath))
        {
            try { VaultSettings.SaveVaultLocation(VaultSettings.DefaultDirectory); } catch { }
        }
        RefreshMode();
    }

    private void Input_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            e.Handled = true;
            _ = SubmitAsync();
        }
    }

    private void ActionBtn_Click(object sender, RoutedEventArgs e) => _ = SubmitAsync();

    private async Task SubmitAsync()
    {
        if (!ActionBtn.IsEnabled) return;

        var password = PasswordInput.Password;
        if (string.IsNullOrEmpty(password))
        {
            SetStatus("总密码不能为空", isError: true);
            return;
        }

        if (_isSetup && password != ConfirmInput.Password)
        {
            SetStatus("两次总密码不一致", isError: true);
            return;
        }

        ActionBtn.IsEnabled = false;
        SetStatus(_isSetup ? "正在创建密码库…" : "正在解锁密码库…", isError: false);

        try
        {
            List<PasswordRecord> records;
            if (_isSetup)
            {
                await Task.Run(() =>
                {
                    VaultCore.CreateVault(_vaultPath, password, Array.Empty<PasswordRecord>());
                    if (_persistLocation)
                    {
                        try
                        {
                            VaultSettings.SaveVaultLocation(Path.GetDirectoryName(_vaultPath)!);
                        }
                        catch
                        {
                            try { if (File.Exists(_vaultPath)) File.Delete(_vaultPath); } catch { }
                            throw;
                        }
                    }
                });
                records = new List<PasswordRecord>();
            }
            else
            {
                records = await Task.Run(() => VaultCore.LoadVault(_vaultPath, password));
            }

            var mainWin = new MainWindow(password, records, _vaultPath);
            Application.Current.MainWindow = mainWin;
            mainWin.Show();
            Close();
        }
        catch (Exception)
        {
            ActionBtn.IsEnabled = true;
            SetStatus(_isSetup ? "密码库创建失败" : "总密码错误或密码库已损坏", isError: true);
        }
    }

    private void SetStatus(string text, bool isError)
    {
        StatusText.Text = text;
        StatusText.Foreground = (Brush)FindResource(isError ? "ErrorBrush" : "MutedBrush");
    }
}
