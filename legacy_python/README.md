# Password Service

一个简单的本地 Windows 密码管理工具，使用 Python 和 Tkinter 编写。
密码保存在本机加密 vault 中，不使用数据库、不连接网络。

## 启动

需要 Python 3.10 或更高版本。在项目目录运行：

```powershell
python password_saver.py
```

## 加密密码库位置

程序使用唯一的本地加密文件：

`%USERPROFILE%\Documents\PasswordSaver\passwords.enc`

例如：

`C:\Users\<User>\Documents\PasswordSaver\passwords.enc`

首次启动会要求设置 Master Password；后续启动必须先解锁 vault。
保存会将内存中的全部 records 重新加密并原子写入，不会覆盖旧 vault，除非一次完整写入成功。

## 随机生成密码

长度支持：

- 8 位
- 16 位
- 32 位
- 自定义长度（1 到 256 位）

字符类型可以独立选择：

- 大写字母：`A-Z`
- 小写字母：`a-z`
- 数字：`0-9`
- 符号：程序内置的安全特殊字符集合

每个已选择的字符类型至少会在生成结果中出现一次。随机生成使用 Python 的 `secrets` 模块。

如果没有选择任何字符类型，程序不会生成密码。

## 手动输入和保存

可以直接填写名称和密码，也可以先随机生成再手动修改密码。

手动密码不受随机生成器的长度和字符类型选项限制，输入内容会原样保存。

保存记录会写入加密 ciphertext，磁盘上不会出现明文名称、密码或 Master Password。

## 密码查询

在名称输入框中填写关键词后点击“查询”。程序只搜索当前已解锁的内存 records，支持：

- 名称模糊匹配
- 英文大小写不敏感
- 中文名称查询
- 多条匹配结果
- 同名记录按最新保存顺序优先显示

匹配名称会显示在右侧列表中。选择名称后，左侧密码框才显示对应密码，默认保持隐藏。

密码框内的图标可以显示或隐藏密码，也可以复制真实密码内容。复制时不会复制中文引号。

匹配结果较多时，列表会在超过可见行数后显示滚动条，不会撑大界面。

## 其它操作

程序还支持：

- 显示或隐藏主密码框内容
- 复制主密码
- 打开密码库所在文件夹

所有操作都在本机完成。

## Encrypted Vault（Phase 1 + Phase 2）

项目包含独立的 `vault.py` 加密密码库核心，并已接入 Tkinter 启动解锁流程。Phase 2 不会读取、迁移或修改现有 `passwords.md`。

加密设计：

- KDF：Argon2id
- 默认参数：64 MiB memory、3 iterations、4 lanes
- 密钥长度：256 bit
- AEAD：AES-256-GCM
- Salt：每次保存随机生成 16 bytes
- Nonce：每次保存随机生成 12 bytes
- Python library：`cryptography>=49.0.0,<50.0.0`
- 保存方式：临时文件写入、`flush`、`fsync`、原子替换

加密 vault 使用版本化 JSON envelope：

```text
version
kdf + kdf_parameters
salt
cipher
nonce
ciphertext
```

名称和密码组成的 records payload 会整体加密，只存在于 ciphertext 中。Master Password、明文名称和明文密码都不会写入 envelope。主界面保存和查询只使用当前解锁后的内存 records。

安装依赖：

```powershell
python -m pip install -r requirements.txt
```

运行加密核心测试：

```powershell
python -m unittest -v test_vault.py
```
