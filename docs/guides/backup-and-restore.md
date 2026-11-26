# 安装、备份与恢复

## 验证和启动发行包

从项目的 GitHub Releases 下载与本机平台和架构对应的发行包，以及同一版本的 `SHA256SUMS`。Intel、AMD 64 位处理器选择 `amd64`，Apple Silicon 和其他 64 位 ARM 设备选择 `arm64`。将校验结果与可信发行页提供的摘要核对后再解压。

| 平台 | 文件名 | 启动程序 |
| --- | --- | --- |
| macOS Web | `imon-web_darwin_amd64.tar.gz` 或 `imon-web_darwin_arm64.tar.gz` | `./imon` |
| Linux Web | `imon-web_linux_amd64.tar.gz` 或 `imon-web_linux_arm64.tar.gz` | `./imon` |
| Windows Web | `imon-web_windows_amd64.zip` 或 `imon-web_windows_arm64.zip` | `.\imon.exe` |

只下载一个发行包时，可以将下列命令中的占位符替换为该文件名，然后核对输出与 `SHA256SUMS` 中对应的一行。

**macOS**

```sh
shasum -a 256 '<ARCHIVE_NAME>'
tar -xzf '<ARCHIVE_NAME>'
./imon --version
./imon
```

**Linux**

```sh
sha256sum '<ARCHIVE_NAME>'
tar -xzf '<ARCHIVE_NAME>'
./imon --version
./imon
```

**Windows PowerShell**

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath '<ARCHIVE_NAME>'
Expand-Archive -LiteralPath '<ARCHIVE_NAME>' -DestinationPath '<EXTRACT_DIR>'
Set-Location -LiteralPath '<EXTRACT_DIR>'
.\imon.exe --version
.\imon.exe
```

在本机浏览器打开程序打印的 `Panel URL:`。使用自定义数据目录时，首次运行可让程序创建目录。macOS 和 Linux 的已有数据目录须归当前用户所有且权限为 `0700`。Windows 版要求私有数据目录，建议让程序创建新的目录。

## 创建备份

1. 在程序终端按 Ctrl+C，等待进程退出。使用与正常启动相同的用户和 `--data-dir`。
2. 在本地支持硬链接的文件系统上选一个已有的私有目录，给备份指定新文件名。目标文件已存在时，命令会报错并保留原文件。
3. 另行保管应用引用的 SSH 密钥、kubeconfig 及其关联文件、Telegram 令牌和 SMTP 凭据。数据库备份包含配置、采集数据、告警历史和这些文件的引用，请将备份保存在私有目录中。

```sh
./imon --data-dir '<DATA_DIR>' --backup '<BACKUP_FILE>'
```

```powershell
.\imon.exe --data-dir '<DATA_DIR>' --backup '<BACKUP_FILE>'
```

使用系统默认数据目录时省略 `--data-dir`。客户端生成的备份为独立的 SQLite 文件。

## 恢复及回滚

1. 停止使用目标数据目录的 Imon 进程。使用下面的命令先恢复到单独的目录，检查备份中的绑定、设置和告警历史。启动恢复环境会加载备份中的轮询和通知设置。在仅核对数据时，可以先断开远端网络，直至核对结束。
2. 正式恢复时，把相同命令中的 `<ISOLATED_DATA_DIR>` 换成实际数据目录。需要启停远端服务、采集或发通知时，在原引用路径提供凭据文件，或者在界面更改相应引用并重新校验连接。
3. 恢复成功后重新启动客户端。若目标目录原有数据，恢复命令会打印其回滚副本路径。需要撤销恢复时，停止客户端，把该副本路径作为同一个 `--restore` 命令的输入。

```sh
./imon --data-dir '<ISOLATED_DATA_DIR>' --restore '<BACKUP_FILE>'
./imon --data-dir '<ISOLATED_DATA_DIR>'
```

```powershell
.\imon.exe --data-dir '<ISOLATED_DATA_DIR>' --restore '<BACKUP_FILE>'
.\imon.exe --data-dir '<ISOLATED_DATA_DIR>'
```

备份中待投递或发送中的通知会在恢复时标记为「结果未知」，用于避免重复发送。请保留原备份和回滚副本，直到确认恢复后的配置及历史数据符合预期。

## 更新

正式发布的 Web 包已预设 GitHub Releases 仓库。如果使用本地构建，可在启动时使用 `--release-repo '<GITHUB_OWNER>/<GITHUB_REPO>'` 指定公开的发布仓库。客户端每次启动后首次打开面板时检查一次更新。有新版本时，侧栏底部的版本号显示红点，点击可查看发布说明和 GitHub 发布页。

在 macOS 和 Linux 上点击 [更新]，应用下载并校验发布包、备份 SQLite、替换当前程序并自动重启。原面板在同一地址和会话中重新连接。新版本启动失败时，程序回退到旧版本及对应的数据状态并在面板报告结果。

Windows 或不可进行原地替换的安装位置可从气泡打开 GitHub 发布页，按前面的安装步骤校验并解压新包。手动更新前先备份数据、保留旧程序并退出当前客户端；使用过自定义数据目录时，仍传入同一个 `--data-dir`。手动回退时，停止新进程，用旧版客户端恢复升级前的备份，再启动旧版。

## 维护者构建发行包

在 macOS 或 Linux 从项目根目录执行，使用项目 `go.mod` 声明的 Go 工具链、`tar`、`zip` 和 SHA-256 工具。第三个参数可预设公开的 GitHub 发行仓库，作为客户端检查更新的来源。

```sh
./packaging/release/build.sh '<VERSION_TAG>' '<OUTPUT_DIRECTORY>' '<GITHUB_OWNER>/<GITHUB_REPO>'
```

使用 `v主版本.次版本.修订号` 格式的实际版本标签，例如 `v1.0.0`。输出位于 `<OUTPUT_DIRECTORY>/<VERSION_TAG>`，包含六个客户端发行包和 `SHA256SUMS`。依次构建并校验两个架构的 Linux 防火墙读取器，再将它们内嵌到每个客户端。若省略输出目录，默认写入项目的 `dist/`。发布时将输出文件原名上传到同标签的 GitHub Release。
