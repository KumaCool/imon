# Imon

Imon 是 infra monitor 的缩写，是一个**轻量化、超小型的本地监控应用**。它运行在用户自己的电脑上，通过 SSH 和 Kubernetes API 管理并观察多台 Linux 主机或 Kubernetes 集群，尽可能减少中心端和目标端的性能开销。

项目首版定位为：**一个不依赖独立服务器、不要求目标机常驻 Agent、面向多主机和多集群的本地监控工具**。

## 设计定位

- 中心端是一个本地单文件程序，Web 版默认只监听 `127.0.0.1`。
- 目标主机通过 SSH 连接，集群通过本机 kubeconfig 和 Context 连接。
- 目标机无需常驻采集 Agent。主机辅助程序在采集防火墙、读取端口所属进程、启停受支持的 systemd 服务或更新自身时按需运行。
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
- 主机辅助程序：按需安装、更新、卸载和核验。支持读取监听端口的进程，读取 `ufw`、`nftables` 和 `iptables-legacy` 规则，以及启停受支持的 systemd 服务。
- 本地数据：使用 SQLite 保存绑定、采集快照、规则和事件，支持备份与恢复。
- 版本更新：Web 版和桌面版启动后首次打开面板时检查 GitHub Releases。侧栏版本号显示更新来源、新版本和发布说明。macOS、Linux 的 Web 版支持一键更新，桌面版和 Windows Web 版可下载对应安装包。

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
- 主机辅助程序通过 SSH 安装时需要 `/usr/bin/base64`

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
repo=$(sh ./packaging/release/repository.sh "$PWD")
./imon --release-repo "$repo"
```

启动后打开终端输出的 `Panel URL`，默认地址为：

```text
http://127.0.0.1:8765/
```

端口被占用时：

```sh
./imon --port 8876 --release-repo "$repo"
```

### 构建 Web 发布包

发布脚本默认使用 GitHub `origin` 仓库作为更新来源，也可通过第三个参数指定 `<GITHUB_OWNER>/<GITHUB_REPO>`。

```sh
IMON_HELPER_SIGNING_KEY_FILE='<HELPER_SIGNING_KEY_PEM>' \
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

Web 和桌面发布包使用同一把 Ed25519 私钥签署 Linux 主机辅助程序。首次构建可使用 `openssl genpkey -algorithm ED25519` 在仓库外生成 PKCS#8 PEM，以后发布复用该私钥。仅本地验证可设置 `IMON_ALLOW_UNSIGNED_HELPER=1`，这类构建的辅助程序没有自更新授权。

### 从旧版升级

首次升级到 Imon 时，关闭旧版并重新安装桌面版，或解包后运行新的 Web 命令 `imon`。如果使用原来的默认数据目录，Imon 会在新的默认数据目录尚未创建时自动沿用它。如果使用自定义目录，启动时继续传入原来的 `--data-dir`。Imon 会保留已有的绑定、告警记录和主机授权。辅助程序有新版时，可从主机列表的「操作 → 更新授权」升级。

## 命令行参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--port` | `8765` | 本地 Web 面板端口 |
| `--data-dir` | 用户级应用目录 | SQLite、锁文件和本地状态目录 |
| `--release-repo` | Web 和桌面发布包预设，直接源码构建为空 | 指定 GitHub Releases 仓库，格式为 `owner/repo` |
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
- 绑定、解绑、服务启停和主机辅助程序维护按连接版本核验，避免旧任务覆盖新连接结果。
- 主机辅助程序集中承载 Imon 所需的主机权限，包括读取防火墙规则、读取监听端口的进程信息、启停受支持的 systemd 服务和更新自身。安装、迁移和更新都无需重启主机。
- 首次安装时，Imon 优先使用 SSH 账号已有的安装权限。权限不足时，用户确认上传后，由管理员在主机上执行一次安装命令。旧版授权缺少自更新入口，需要执行一次相同的迁移流程。
- 迁移或首次安装后，在主机列表点击「更新授权」，已安装的辅助程序会校验签名、架构和版本，再替换自身。更新沿用绑定的 SSH 账号及现有授权，无需管理员再次登录主机。
- 自 v0.1.1 起，安装或迁移后的辅助程序支持直接卸载授权。点击「卸载授权」或确认解绑时，Imon 使用同一 SSH 账号撤销自己的授权并清理相关文件。已安装的旧授权如果缺少卸载入口，可使用管理员凭据或手动维护脚本完成清理。

## 文档

- [更新日志](CHANGELOG.md)
- [首版功能清单](docs/guides/v1-features.md)
- [备份与恢复](docs/guides/backup-and-restore.md)
- [发布验证记录](docs/guides/v1-release-verification.md)
- [界面草图](docs/design/v1-ui-wireframes.md)
- [技术方案](docs/solutions/02-v0.1.0-desktop-and-collection.md)
- [完整卸载技术方案](docs/solutions/03-complete-uninstall.md)
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
