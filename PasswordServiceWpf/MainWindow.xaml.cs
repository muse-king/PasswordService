using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace PasswordServiceWpf;

public partial class MainWindow : Window
{
    private readonly string _masterPassword;
    private List<PasswordRecord> _records;
    private string _vaultPath;

    private bool _pwdVisible;
    private bool _syncingPwd;
    private bool _selectedPwdVisible;
    private readonly List<(int Index, PasswordRecord Record)> _currentMatches = new();
    private string? _lastCopiedSecret;
    private DispatcherTimer? _clipboardClearTimer;

    public MainWindow(string masterPassword, List<PasswordRecord> records, string vaultPath)
    {
        InitializeComponent();
        _masterPassword = masterPassword;
        _records = records;
        _vaultPath = vaultPath;

        SourceInitialized += (_, _) => UnlockWindow.ApplyDarkTitleBar(this);
        Loaded += (_, _) =>
        {
            VaultPathText.Text = _vaultPath;
            NameInput.Focus();
        };
    }

    private void SetFooterStatus(string text, string brushKey = "MutedBrush")
    {
        FooterStatusText.Text = text;
        FooterStatusText.Foreground = (Brush)FindResource(brushKey);
    }

    private void CopyToClipboardWithAutoClear(string secret)
    {
        try
        {
            Clipboard.SetText(secret);
            _lastCopiedSecret = secret;
            _clipboardClearTimer?.Stop();
            _clipboardClearTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
            _clipboardClearTimer.Tick += (_, _) =>
            {
                _clipboardClearTimer?.Stop();
                try
                {
                    if (_lastCopiedSecret != null && Clipboard.ContainsText() && Clipboard.GetText() == _lastCopiedSecret)
                    {
                        Clipboard.Clear();
                        _lastCopiedSecret = null;
                    }
                }
                catch { }
            };
            _clipboardClearTimer.Start();
            SetFooterStatus("● 已复制（30 秒后自动清空剪贴板）", "SuccessBrush");
        }
        catch
        {
            SetFooterStatus("● 错误: 复制失败", "ErrorBrush");
        }
    }

    private string GetCurrentPwdText() => _pwdVisible ? PwdPlainInput.Text : PwdMaskedInput.Password;

    private void SetCurrentPwdText(string value)
    {
        _syncingPwd = true;
        PwdPlainInput.Text = value;
        PwdMaskedInput.Password = value;
        _syncingPwd = false;
    }

    private void PwdPlainInput_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_syncingPwd) return;
        _syncingPwd = true;
        PwdMaskedInput.Password = PwdPlainInput.Text;
        _syncingPwd = false;
    }

    private void PwdMaskedInput_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (_syncingPwd) return;
        _syncingPwd = true;
        PwdPlainInput.Text = PwdMaskedInput.Password;
        _syncingPwd = false;
    }

    private void TogglePwd_Click(object sender, RoutedEventArgs e)
    {
        _pwdVisible = !_pwdVisible;
        if (_pwdVisible)
        {
            PwdPlainInput.Visibility = Visibility.Visible;
            PwdMaskedInput.Visibility = Visibility.Collapsed;
            TogglePwdBtn.Content = "◉";
        }
        else
        {
            PwdPlainInput.Visibility = Visibility.Collapsed;
            PwdMaskedInput.Visibility = Visibility.Visible;
            TogglePwdBtn.Content = "○";
        }
    }

    private void CopyPwd_Click(object sender, RoutedEventArgs e)
    {
        var pwd = GetCurrentPwdText();
        if (string.IsNullOrEmpty(pwd))
        {
            SetFooterStatus("● 错误: 密码为空", "ErrorBrush");
            return;
        }
        CopyToClipboardWithAutoClear(pwd);
    }

    private void LenPreset_Checked(object sender, RoutedEventArgs e) { }
    private void LenCustom_Checked(object sender, RoutedEventArgs e) => CustomLenInput?.Focus();
    private void CustomLenInput_GotFocus(object sender, RoutedEventArgs e) => LenCustomRadio.IsChecked = true;

    private void Generate_Click(object sender, RoutedEventArgs e)
    {
        int length = 16;
        if (Len8Radio.IsChecked == true) length = 8;
        else if (Len16Radio.IsChecked == true) length = 16;
        else if (Len32Radio.IsChecked == true) length = 32;
        else if (LenCustomRadio.IsChecked == true)
        {
            if (!int.TryParse(CustomLenInput.Text.Trim(), out length))
            {
                SetFooterStatus("● 错误: 请输入自定义长度", "ErrorBrush");
                return;
            }
        }

        try
        {
            var generated = PasswordGenerator.Generate(
                length,
                UpperCheck.IsChecked == true,
                LowerCheck.IsChecked == true,
                DigitsCheck.IsChecked == true,
                SymbolsCheck.IsChecked == true);
            SetCurrentPwdText(generated);
            SetFooterStatus("● 已生成随机密码", "SuccessBrush");
        }
        catch (Exception ex)
        {
            SetFooterStatus($"● 错误: {ex.Message}", "ErrorBrush");
        }
    }

    private async void Save_Click(object sender, RoutedEventArgs e)
    {
        var name = NameInput.Text;
        var pwd = GetCurrentPwdText();
        if (string.IsNullOrWhiteSpace(name))
        {
            SetFooterStatus("● 错误: 名称不能为空", "ErrorBrush");
            return;
        }
        if (string.IsNullOrEmpty(pwd))
        {
            SetFooterStatus("● 错误: 密码不能为空", "ErrorBrush");
            return;
        }

        SaveBtn.IsEnabled = false;
        SetFooterStatus("● 正在加密保存…", "MutedBrush");
        var updated = new List<PasswordRecord>(_records) { new(name, pwd) };

        try
        {
            await Task.Run(() => VaultCore.SaveVault(_vaultPath, _masterPassword, updated));
            _records = updated;
            NameInput.Text = "";
            SetCurrentPwdText("");
            SetFooterStatus("● 保存成功", "SuccessBrush");
        }
        catch (Exception ex)
        {
            SetFooterStatus($"● 保存失败: {ex.Message}", "ErrorBrush");
        }
        finally
        {
            SaveBtn.IsEnabled = true;
        }
    }

    private void SearchInput_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            e.Handled = true;
            PerformSearch();
        }
    }

    private void Search_Click(object sender, RoutedEventArgs e) => PerformSearch();

    private void ShowAll_Click(object sender, RoutedEventArgs e) => PerformSearch(showAll: true);

    private void PerformSearch(bool showAll = false)
    {
        _currentMatches.Clear();
        MatchList.Items.Clear();
        SelectedNameText.Text = "";
        SelectedPwdText.Text = "";
        SelectedActionsPanel.Visibility = Visibility.Collapsed;
        _selectedPwdVisible = false;

        var query = SearchInput.Text.Trim();
        if (!showAll && query != "*" && string.IsNullOrEmpty(query))
        {
            SearchStatusText.Text = "请输入名称";
            return;
        }

        bool listAll = showAll || query == "*";
        for (int i = _records.Count - 1; i >= 0; i--)
        {
            if (listAll || _records[i].Name.Contains(query, StringComparison.OrdinalIgnoreCase))
            {
                _currentMatches.Add((i, _records[i]));
                MatchList.Items.Add(_records[i].Name);
            }
        }

        SearchStatusText.Text = _currentMatches.Count == 0
            ? "未找到匹配的密码"
            : $"共 {_currentMatches.Count} 条，请选择右侧结果";
    }

    private void MatchList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        int idx = MatchList.SelectedIndex;
        if (idx < 0 || idx >= _currentMatches.Count)
        {
            SelectedActionsPanel.Visibility = Visibility.Collapsed;
            return;
        }

        var record = _currentMatches[idx].Record;
        _selectedPwdVisible = false;
        SelectedNameText.Text = record.Name;
        SelectedPwdText.Text = new string('•', Math.Max(8, record.Password.Length));
        ToggleSelectedBtn.Content = "显示";
        SelectedActionsPanel.Visibility = Visibility.Visible;
    }

    private void ToggleSelected_Click(object sender, RoutedEventArgs e)
    {
        int idx = MatchList.SelectedIndex;
        if (idx < 0 || idx >= _currentMatches.Count) return;

        var pwd = _currentMatches[idx].Record.Password;
        _selectedPwdVisible = !_selectedPwdVisible;
        SelectedPwdText.Text = _selectedPwdVisible ? pwd : new string('•', Math.Max(8, pwd.Length));
        ToggleSelectedBtn.Content = _selectedPwdVisible ? "隐藏" : "显示";
    }

    private void CopySelected_Click(object sender, RoutedEventArgs e)
    {
        int idx = MatchList.SelectedIndex;
        if (idx < 0 || idx >= _currentMatches.Count) return;
        CopyToClipboardWithAutoClear(_currentMatches[idx].Record.Password);
    }

    private async void Rename_Click(object sender, RoutedEventArgs e)
    {
        int idx = MatchList.SelectedIndex;
        if (idx < 0 || idx >= _currentMatches.Count) return;

        var (recordIndex, record) = _currentMatches[idx];
        var newName = PromptForNewName(record.Name);
        if (newName == null) return;

        newName = newName.Trim();
        if (string.IsNullOrEmpty(newName))
        {
            SetFooterStatus("● 错误: 名称不能为空", "ErrorBrush");
            return;
        }

        if (MessageBox.Show(this, $"确认将名称修改为“{newName}”吗？", "确认重命名", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;

        RenameBtn.IsEnabled = false;
        var updated = new List<PasswordRecord>(_records);
        updated[recordIndex] = record with { Name = newName };

        try
        {
            await Task.Run(() => VaultCore.SaveVault(_vaultPath, _masterPassword, updated));
            _records = updated;
            PerformSearch();
            SetFooterStatus("● 名称已修改，密码保持不变", "SuccessBrush");
        }
        catch (Exception ex)
        {
            SetFooterStatus($"● 改名失败: {ex.Message}", "ErrorBrush");
        }
        finally
        {
            RenameBtn.IsEnabled = true;
        }
    }

    private string? PromptForNewName(string initialValue)
    {
        var dlg = new Window
        {
            Title = "改名字",
            Width = 360,
            Height = 160,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Owner = this,
            ResizeMode = ResizeMode.NoResize,
            Background = (Brush)FindResource("BgBrush"),
        };
        var panel = new StackPanel { Margin = new Thickness(18) };
        panel.Children.Add(new TextBlock { Text = "新名称：", Foreground = (Brush)FindResource("MutedBrush"), Margin = new Thickness(0, 0, 0, 6) });
        var box = new TextBox
        {
            Text = initialValue,
            Background = (Brush)FindResource("EntryBgBrush"),
            Foreground = (Brush)FindResource("TextBrush"),
            CaretBrush = (Brush)FindResource("TextBrush"),
            BorderBrush = (Brush)FindResource("BorderBrush"),
            Padding = new Thickness(6, 4, 6, 4),
        };
        panel.Children.Add(box);

        string? result = null;
        var btnPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 14, 0, 0) };
        var okBtn = new Button { Content = "确定", Style = (Style)FindResource("DarkButton"), Padding = new Thickness(14, 5, 14, 5), Margin = new Thickness(0, 0, 8, 0), IsDefault = true };
        var cancelBtn = new Button { Content = "取消", Style = (Style)FindResource("SecondaryButton"), Padding = new Thickness(14, 5, 14, 5), IsCancel = true };
        okBtn.Click += (_, _) => { result = box.Text; dlg.DialogResult = true; };
        btnPanel.Children.Add(okBtn);
        btnPanel.Children.Add(cancelBtn);
        panel.Children.Add(btnPanel);
        dlg.Content = panel;
        box.Focus();
        box.SelectAll();
        return dlg.ShowDialog() == true ? result : null;
    }

    private async void Delete_Click(object sender, RoutedEventArgs e)
    {
        int idx = MatchList.SelectedIndex;
        if (idx < 0 || idx >= _currentMatches.Count) return;

        if (MessageBox.Show(this, "确定删除当前选中的密码记录吗？", "删除密码", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;

        DeleteBtn.IsEnabled = false;
        int recordIndex = _currentMatches[idx].Index;
        var updated = new List<PasswordRecord>(_records);
        updated.RemoveAt(recordIndex);

        try
        {
            await Task.Run(() => VaultCore.SaveVault(_vaultPath, _masterPassword, updated));
            _records = updated;
            PerformSearch();
            SetFooterStatus("● 密码记录已删除", "SuccessBrush");
        }
        catch (Exception ex)
        {
            SetFooterStatus($"● 删除失败: {ex.Message}", "ErrorBrush");
        }
        finally
        {
            DeleteBtn.IsEnabled = true;
        }
    }

    private async void ChangeLocation_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog { Title = "选择密码库文件夹" };
        if (dialog.ShowDialog(this) != true) return;

        var targetDir = dialog.FolderName;
        SetFooterStatus("● 正在迁移密码库…", "MutedBrush");
        try
        {
            var newPath = await Task.Run(() =>
            {
                var migrated = VaultSettings.MigrateVault(_vaultPath, targetDir, _masterPassword, _records);
                VaultSettings.SaveVaultLocation(targetDir);
                return migrated;
            });
            _vaultPath = newPath;
            VaultPathText.Text = _vaultPath;
            SetFooterStatus("● 密码库已迁移到新位置，旧副本仍保留", "SuccessBrush");
        }
        catch (Exception ex)
        {
            SetFooterStatus($"● 迁移失败: {ex.Message}", "ErrorBrush");
        }
    }

    private void OpenFolder_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var dir = Path.GetDirectoryName(_vaultPath);
            if (!string.IsNullOrEmpty(dir))
            {
                Process.Start(new ProcessStartInfo("explorer.exe", dir) { UseShellExecute = true });
                SetFooterStatus("● 已打开所在文件夹", "MutedBrush");
            }
        }
        catch
        {
            SetFooterStatus("● 错误: 打开所在文件夹失败", "ErrorBrush");
        }
    }
}
