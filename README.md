# Password Service

一个轻量、快速、纯本地运行的 Windows 加密密码管理工具（基于 **.NET 8 WPF**）。  
A lightweight, fast, local-first encrypted password manager for Windows, built with **.NET 8 WPF**.

---

## 中文说明

### 核心特性
- **纯本地加密，无网络、无数据库**：所有密码均保存在本机或你指定的文件夹（如 iCloud 同步目录）中的单一加密文件 `passwords.enc`。
- **强加密方案**：
  - 密钥派生：**Argon2id**（64 MiB 内存、3 次迭代、4 线程）
  - 认证加密：**AES-256-GCM**（每次保存随机生成 16 字节 Salt 和 12 字节 Nonce）
  - 原子写入：临时文件写入、`Flush(true)` 后原子替换，防止意外断电或中断损坏数据。
- **原生硬件加速界面**：
  - 标准 **16:9（960×540）** 双栏无滚动条深色界面，启动即用。
  - 加解密均在后台线程异步执行，不卡顿界面。
- **完整密码管理功能**：
  - 首次打开引导选择密码库位置（或使用默认位置 `%USERPROFILE%\Documents\PasswordSaver\passwords.enc`），解锁界面支持随时切换位置。
  - 随机密码生成：支持 8 / 16 / 32 位及 1–256 位自定义长度，可独立勾选 `A-Z`、`a-z`、`0-9` 和安全符号，确保每种已选类型至少出现一次。
  - 密码查询：支持中英文模糊搜索、大小写不敏感、最新优先，以及“显示全部”功能。
  - 安全剪贴板：复制密码后 **30 秒自动清空剪贴板**（仅当剪贴板内容未被覆盖时）。

### 运行与构建
需要 **.NET 8.0 SDK (Windows)**：
```powershell
cd PasswordServiceWpf
dotnet run
```
发布独立运行目录：
```powershell
dotnet publish PasswordServiceWpf/PasswordServiceWpf.csproj -c Release -o PasswordServiceWpf/publish
```

> `legacy_python/` 目录保留了早期 Python + Tkinter 版本的加密核心（`vault.py`）与单元测试（`test_vault.py`），两者加密格式完全兼容。

---

## English

### Features
- **Local-First & Offline**: No database, no network calls. All records are stored in a single encrypted file (`passwords.enc`) in your chosen directory (e.g., local folder or iCloud Drive).
- **Strong Cryptography**:
  - KDF: **Argon2id** (64 MiB memory, 3 iterations, 4 lanes)
  - AEAD: **AES-256-GCM** with a fresh 16-byte random salt and 12-byte random nonce on every save
  - Atomic writes: Writes to a temporary file, flushes to disk, and atomically replaces the target file.
- **Native Hardware-Accelerated UI**:
  - Clean **16:9 (960×540)** two-column dark-mode WPF interface with no scrollbars.
  - Background async encryption/decryption keeps the UI responsive at all times.
- **Password Management**:
  - First-run location picker (or default `%USERPROFILE%\Documents\PasswordSaver\passwords.enc`) with quick location switching.
  - Cryptographically secure password generator (`RandomNumberGenerator`) supporting 8 / 16 / 32 or custom lengths (1–256) and independent character-class toggles.
  - Case-insensitive fuzzy search, "Show All" listing, rename, delete, and **30-second clipboard auto-clear**.

### Build & Run
Requires **.NET 8.0 SDK (Windows)**:
```powershell
cd PasswordServiceWpf
dotnet run
```
Publish release build:
```powershell
dotnet publish PasswordServiceWpf/PasswordServiceWpf.csproj -c Release -o PasswordServiceWpf/publish
```

> The `legacy_python/` directory contains the original Python vault core (`vault.py`) and unit tests (`test_vault.py`). The WPF version is 100% format-compatible with it.
