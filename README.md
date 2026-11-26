# Imon

Imon 是 infra monitor 的缩写，是一个**轻量化、超小型的本地监控应用**。它运行在用户自己的电脑上，通过 SSH 和 Kubernetes API 管理并观察多台 Linux 主机或 Kubernetes 集群，尽可能减少中心端和目标端的性能开销。

项目首版定位为：**一个不依赖独立服务器、不要求目标机常驻 Agent、面向多主机和多集群的本地监控工具**。

当前版本：`v0.1.0`

## 设计定位

- 中心端是一个本地单文件程序，Web 版默认只监听 `127.0.0.1`。
- 目标主机通过 SSH 连接，集群通过本机 kubeconfig 和 Context 连接。
- 目标机不安装常驻采集 Agent；防火墙只读辅助程序仅在需要防火墙采集或维护时使用。
- 页面数据默认按需采集；只有关联告警规则的数据才进入主动轮询。
- 主机和集群采集跨目标并发，但有固定上限：主机最多 4 个、集群最多 2 个；同一目标不会重叠采集。
- 采集失败进入告警事件，不依赖高频轮询持续占用网络和目标机资源。
- 产品面向运维观察和轻量告警，不定位为长期指标存储、日志平台或大型监控集群。

## 功能

- 主机管理：绑定、编辑、解绑 Linux 主机，查看系统、SSH 状态和资源摘要。
- 集群管理：绑定 kubeconfig/Context，查看节点、命名空间、Pod、Deployment 和 Service。
- 主机详情：CPU、内存、磁盘、网络接口、路由、端口和防火墙规则。
- 服务管理：统一查看宿主机 systemd 服务和 Kubernetes 工作负载，支持筛选、资源展示和排序；具备授权时可操作服务。
- 告警与事件：创建规则，记录采集失败、资源异常、节点离线和服务异常，并发送到面板、Telegram 或邮箱。
- 采集设置：配置轮询开关、主机/网络/集群采集间隔和超时；支持在当前页面手动采集。
- 防火墙辅助程序：按需安装、卸载和核验 Linux 防火墙只读辅助程序，支持 `ufw`、`nftables` 和 `iptables-legacy`。
- 本地数据：使用 SQLite 保存绑定、采集快照、规则和事件，支持备份与恢复。
- Web 版更新：正式发布包首次打开面板时检查 GitHub Releases。侧栏版本号可显示新版本和发布说明。macOS、Linux 支持一键更新，Windows 可从发布页下载安装包。

## 工作方式

```text
浏览器（Web 版）或原生窗口（桌面候选）
  │  本地界面
  ▼
Imon
  ├─ SQLite（本地绑定、快照、规则和事件）
  ├─ SSH ───────── Linux 主机 / systemd / 网络工具
  └─ Kubernetes API ─ kubeconfig Context / 集群资源
```

采集任务由本地调度器管理：每个目标最多一个排队任务和一个运行任务；同一目标的不同数据组按序采集并尽可能复用连接。调度器负责超时、取消、失败退避和请求合并。应用退出或休眠时暂停采集，不补录未观察到的故障。

Web 版和桌面版是独立运行入口，不应同时使用同一个数据目录；桌面版不启动 Web 服务或监听 HTTP 端口。

## 支持范围

### 中心端

Web 发布脚本可交叉构建 macOS、Linux 和 Windows 的 `amd64` 与 `arm64` 归档。各平台的实机测试覆盖范围见[发布验证记录](docs/guides/v1-release-verification.md)。桌面版按各平台构建要求单独打包；各平台的候选状态和验证限制见[桌面构建文档](packaging/desktop/README.md)。Web 版默认只允许本机通过 `127.0.0.1` 访问。

### Linux 主机

- `systemd`
- 可通过 SSH 执行 `/bin/sh`
- 可读取 `/proc`
- GNU `df`
- `iproute2`（网络接口、路由和端口采集）
- 防火墙只读辅助程序通过 SSH 流传输安装时需要 `/usr/bin/base64`

应用不依赖目标账号的默认 Shell，远程采集脚本统一由 `/bin/sh` 执行。绑定时提供本机 SSH 私钥路径即可；服务器公钥由连接过程读取，并通过本机 `known_hosts` 校验。

### Kubernetes 集群

- 使用本机 kubeconfig 和指定 Context。
- 需要访问 Kubernetes API 以及读取节点、命名空间和工作负载资源的 RBAC 权限。
- 不要求 K3s，也不要求 Metrics Server。
- kubeconfig 中的 exec 登录插件需要先经过本地确认。

## 快速开始

从项目的 GitHub Releases 下载与系统和架构匹配的 Web 发布包。校验 `SHA256SUMS` 后解压并启动 `imon`，Windows 使用 `imon.exe`。见[安装、备份与恢复](docs/guides/backup-and-restore.md)。

### 从源码运行 Web 版

在项目根目录使用 Go `1.26.x`，推荐 Go `1.26.11`：

```sh
CGO_ENABLED=0 go build -trimpath -o ./imon ./cmd/imon
./imon
```

启动后打开终端输出的 `Panel URL`，默认地址为：

```text
http://127.0.0.1:8765/
```

端口被占用时：

```sh
./imon --port 8876
```

### 构建 Web 发布包

将 `<GITHUB_OWNER>/<GITHUB_REPO>` 替换为发布仓库，构建时预设在线更新来源。

```sh
GO_BIN='<GO_EXECUTABLE>' ./packaging/release/build.sh v0.1.0 dist/imon '<GITHUB_OWNER>/<GITHUB_REPO>'
```

发布产物位于 `dist/imon/v0.1.0/`。以 macOS Intel 为例：

```sh
mkdir -p /tmp/imon-v010
chmod 700 /tmp/imon-v010
tar -xzf dist/imon/v0.1.0/imon-web_darwin_amd64.tar.gz \
  -C /tmp/imon-v010
/tmp/imon-v010/imon
```

生成后续版本时使用新的 SemVer 标签，例如 `v0.1.1`。发布脚本不会覆盖已经存在的版本目录。

### 从旧版升级

首次升级到 Imon 时，关闭旧版并重新安装桌面版，或解包后运行新的 Web 命令 `imon`。如果使用原来的默认数据目录，Imon 会在新的默认数据目录尚未创建时自动沿用它。如果使用自定义目录，启动时继续传入原来的 `--data-dir`。已有主机和集群绑定、告警记录及防火墙授权可以继续使用。

## 命令行参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--port` | `8765` | 本地 Web 面板端口 |
| `--data-dir` | 用户级应用目录 | SQLite、锁文件和本地状态目录 |
| `--release-repo` | 正式发布包预设，源码构建为空 | 指定 GitHub Releases 仓库，格式为 `owner/repo` |
| `--version` | - | 输出当前版本并退出 |
| `--backup <FILE>` | - | 面板停止时导出 SQLite 备份 |
| `--restore <FILE>` | - | 面板启动前恢复 SQLite 备份 |

同一个数据目录不能同时由 Web 版和桌面版使用。运行期间不要删除 `instance.lock` 或替换数据库文件。

## 性能边界

当前实现通过以下方式控制开销：

- 无中心服务器和远端常驻采集进程。
- 页面只在首次进入或达到采集间隔时采集。
- 没有关联告警规则时，不对目标做后台持续采集。
- 主机并发上限为 4，集群并发上限为 2；更多目标会排队而不会无限创建任务。
- SSH 单组采集默认超时 10 秒，systemd 组默认超时 30 秒；Kubernetes API 请求默认超时 5 秒。
- SQLite 使用 WAL、单写入器和有限读取连接，避免本地数据库连接数无限增长。

发布归档通常约为 8–9 MB（随平台和架构变化）。空闲运行内存会随操作系统、数据库状态和构建方式变化；本项目不把单次本机观测值承诺为所有规模下的固定上限。多目标容量需要结合实际主机数量、采集间隔和告警规则进行压测。

## 安全与权限

- SSH 私钥只从中心端本地路径读取，不写入目标主机。
- 服务器身份使用 `known_hosts` 和已绑定指纹校验；身份变化时停止使用旧连接。
- kubeconfig 和 exec 插件只在本地使用，并要求显式确认不受信任的 exec 登录程序。
- 绑定、解绑、服务启停和防火墙维护按连接版本核验，避免旧任务覆盖新连接结果。
- 普通 SSH 账号权限不足时，防火墙辅助程序安装/卸载可转为脚本上传和人工执行流程。

## 文档

- [首版功能清单](docs/guides/v1-features.md)
- [备份与恢复](docs/guides/backup-and-restore.md)
- [发布验证记录](docs/guides/v1-release-verification.md)
- [界面草图](docs/design/v1-ui-wireframes.md)
- [技术方案](docs/solutions/02-v0.1.0-desktop-and-collection.md)
- [开发计划](docs/plans/02-v0.1.0-desktop-and-collection.md)
- [桌面构建说明](packaging/desktop/README.md)

## 开发与验证

```sh
go test -count=1 ./...
node --check web/app.js
node --check web/smoke.mjs
```

使用与 `go.mod` 声明匹配的 Go 工具链执行测试。发布前应按目标平台重新运行相关构建和冒烟测试，并核对 `dist/imon/<VERSION>/SHA256SUMS`。

## 许可证

本项目以 [MIT License](LICENSE) 发布。
