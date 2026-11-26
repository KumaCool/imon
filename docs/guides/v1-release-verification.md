# V1 发布验证记录

本页分别记录 `v1.0.0` 本地调试包和旧候选包的构建与运行证据。旧候选包不包含本地私钥选择、SSH 自动识别服务器密钥、异步导航加载提示和侧栏一键更新的后续改动。功能范围见 [V1 发布功能清单](v1-features.md)，安装及数据维护见 [安装、备份与恢复](backup-and-restore.md)。

## 本轮本地验证

从项目根目录执行，项目测试、静态检查、本地调试包构建与摘要校验均退出 `0`。共生成 macOS、Linux、Windows 的 amd64 和 arm64 包，六份校验结果均为 `OK`。

```sh
go test -count=1 -race ./...
go vet ./...
GO_BIN='<GO_EXECUTABLE>' sh packaging/release/build.sh v1.0.0 dist/local-debug
(cd dist/local-debug/v1.0.0 && shasum -a 256 -c SHA256SUMS)
```

### 浏览器与本机文件选择

`CHROME_BIN='<CHROME_EXECUTABLE>' node web/smoke.mjs` 使用本地 API 夹具，退出 `0`，输出：

```text
Web smoke passed: asynchronous navigation/history, aligned controls, SSH picker and fingerprint flow, service/target/alert workflows, firewall maintenance, mobile layout, startup check and update restart
```

Go 测试覆盖本地选择接口的鉴权、参数校验、并发、取消、超时、错误脱敏和路径返回。macOS AppleScript 编译通过，但三种平台的原生图形文件选择窗口均未完成实机选取验证。

### macOS amd64 调试包

从 `dist/local-debug/v1.0.0/` 中的历史 macOS amd64 调试包解包并执行 `python3 -B packaging/release/smoke.py '<EXTRACTED_BINARY>' v1.0.0`，退出 `0`，输出：

```text
Backup and overwrite rejection passed
Restore and restart passed (host interval: 71)
Rollback and restart passed (host interval: 72)
```

用全新临时数据目录启动该程序，面板响应包含侧栏版本入口和私钥选择脚本。未传入 `--release-repo`，`GET /api/v1/version/update?startup=1` 返回 `{"can_apply": false, "current": "v1.0.0", "state": "unconfigured"}`。

### Linux amd64 离线一键更新

测试使用本地构建的冒烟测试镜像和 Docker `--network none`。将 `dist/local-debug/v1.0.0` 只读挂到 `/release` 并解包真实的 Linux amd64 `v1.0.0` 客户端；将源码测试构建用 `-X main.version=v1.0.1` 注入版本并按正常客户端归档格式打包。容器内执行 `python3 -uB /verify/update_smoke.py '<HISTORICAL_BINARY>' '<HISTORICAL_ARCHIVE>' --apply-archive '<HISTORICAL_UPDATE_ARCHIVE>'`，退出 `0`，输出：

```text
Release check, HTTPS redirect, tamper rejection, verified staging and reuse passed
reject: v1.0.0 (configured); same address, session and settings
install: v1.0.1 (configured); same address, session and settings
rollback: v1.0.0 (rolled_back); same address, session and settings
```

更新测试实际替换并重启了客户端。回退用例让候选程序写入数据库后启动失败，验证旧程序和原数据库一并恢复。离线发布服务仅用于本地验证；本轮没有发布或访问真实 GitHub Releases。

## 使用当前命名复现历史验证

以下命令使用 Imon 当前的包名。从项目根目录执行。历史验证环境使用 Go 1.26.11、Python 3.14.2。构建需要 `tar`、`zip` 和 SHA-256 工具；容量测试另需 Python 标准库、OpenSSL 及 macOS 或 Linux。本地 HTTP、Kubernetes TLS 服务和数据目录均由测试临时创建。

```sh
go test -count=1 -race ./...
go vet ./...
./packaging/release/build.sh v1.0.0 dist/final
(cd dist/final/v1.0.0 && shasum -a 256 -c SHA256SUMS)
unzip -t dist/final/v1.0.0/imon-web_windows_amd64.zip
unzip -t dist/final/v1.0.0/imon-web_windows_arm64.zip
tar -tzf dist/final/v1.0.0/imon-web_linux_amd64.tar.gz
tar -tzf dist/final/v1.0.0/imon-web_linux_arm64.tar.gz
```

同一输出目录已有此版本时，用新的输出目录重新构建。Linux 可以用 `sha256sum -c SHA256SUMS` 替代 `shasum`。运行解包测试时选择本机可执行的架构；以下命令以 macOS amd64 为例。

```sh
extract_dir=$(mktemp -d)
tar -xzf dist/final/v1.0.0/imon-web_darwin_amd64.tar.gz -C "$extract_dir"
python3 -B packaging/release/smoke.py "$extract_dir/imon" v1.0.0
python3 -B packaging/release/capacity.py "$extract_dir/imon" 12 48
```

Kubernetes 实机测试使用一次性 kind 集群，其 kubeconfig 用于创建并清理测试命名空间及权限。不要使用生产集群的 kubeconfig。

```sh
python3 -u packaging/release/kind_smoke.py "$extract_dir/imon" '<DISPOSABLE_KIND_KUBECONFIG>'
```

Linux amd64 的备份恢复和更新可在无外网的 Docker 容器中验证。将 `<LINUX_TEST_IMAGE>` 替换为已加载且包含 `sh`、`tar`、Python 3.10+ 和 OpenSSL 的 amd64 Linux 镜像。域名别名及测试证书仅在隔离容器内使用；验证脚本不连接 GitHub，不改写宿主机的 DNS 或证书。

```sh
docker run --rm --network none --tmpfs /tmp:exec,mode=1777,size=256m \
  --add-host api.github.com:127.0.0.1 \
  --add-host github.com:127.0.0.1 \
  --add-host release-assets.githubusercontent.com:127.0.0.1 \
  -v "$PWD/dist/final/v1.0.0:/release:ro" -v "$PWD/packaging/release:/verify:ro" \
  '<LINUX_TEST_IMAGE>' sh -ec '
    archive=/release/imon-web_linux_amd64.tar.gz
    tar -xzf "$archive" -C /tmp
    python3 -B /verify/smoke.py /tmp/imon v1.0.0
    python3 -B /verify/update_smoke.py /tmp/imon "$archive"
  '
```

## 容量测量口径

在独立 SQLite 库中，分别通过面板 API 绑定 12 和 48 个拥有独立身份的合成 Kubernetes 集群。客户端验证 HTTPS 服务器证书，模拟服务校验测试令牌；每次 GET 的模拟处理延迟为 15 ms。每集群包含 2 个命名空间、3 个节点、100 个 Pod、50 个 Deployment、50 个 Service 和 50 个用于后端统计的 EndpointSlice；每轮公布 205 条对象快照。关闭自动轮询，重启中心端后手动发起 3 轮采集。每轮核对所有目标的分项结果、已发布快照行数和实际存储行数。

- **排队 p95**：从本地任务入队到模拟 API 收到身份请求，包含连接建立及请求发送时间。
- **API 批次 p95**：从模拟 API 收到身份请求到最后一个响应准备完成，包含两次请求之间的本地处理间隔，不是 Kubernetes 服务端 CPU 时间。
- **中心端峰值 RSS 和 CPU**：只统计绑定完成后重启的面板进程，覆盖三轮采集；不计 Python、Kubernetes 夹具或浏览器。
- **SQLite**：统计逻辑页数及干净退出后的数据文件大小，不含运行中的 WAL 峰值，不等于性能历史长期存储量。

这些测量针对本机回环、固定对象规模和模拟延迟，不是生产环境吞吐、内存或磁盘上限。

## 历史候选包结果

以下各项退出码均为 `0`。包位于 `dist/final/v1.0.0/`，未上传 GitHub。

| 项目 | 实际结果 |
| --- | --- |
| Go 测试及静态检查 | `go test -count=1 -race ./...` 与 `go vet ./...` 通过。 |
| 构建与归档 | macOS / Linux / Windows 各生成 amd64、arm64 两个包，六个文件的 SHA-256 均为 `OK`；两个 Windows ZIP 完整性通过，两个 Linux tar.gz 列出客户端与安装文档，未出现 macOS xattr 警告。 |
| macOS amd64、Linux amd64 | 从各自发布包解包运行，备份与拒绝覆盖、恢复后重启、回滚后重启均通过。恢复读取到测试轮询间隔 71 秒，回滚后恢复为 72 秒。 |
| Linux amd64 更新链路 | 隔离容器中通过 Release 检查、HTTPS 重定向、篡改包拒收、校验后落盘和复用。验证使用本地 GitHub TLS 夹具，未请求实际 GitHub。 |
| Kubernetes v1.37.0（kind） | 最终 macOS amd64 包运行成功：手动采集 Deployment；只读凭据下停止返回 HTTP 403；单独配置限定到测试命名空间和 Deployment 的写权限后，副本收敛至 0，启动后恢复至 2。 |
| 其他平台 | macOS arm64、Linux arm64、Windows amd64 与 Windows arm64 只完成交叉构建及归档校验，未运行。 |

两个原生平台的备份恢复脚本均输出：

```text
Backup and overwrite rejection passed
Restore and restart passed (host interval: 71)
Rollback and restart passed (host interval: 72)
```

浏览器冒烟测试执行 `CHROME_BIN='<CHROME_EXECUTABLE>' node web/smoke.mjs`，退出码 `0`。测试使用本地 API 夹具，覆盖会话、服务筛选与启停状态、目标测试和绑定、未确认操作重试、登录插件确认、性能数据缺口、监听端口、防火墙授权、规则创建与事件阅读、通知设置、移动端宽度及更新检查和下载。

Linux 宿主机冒烟测试执行 `GO_BIN='<GO_EXECUTABLE>' sh packaging/linux-smoke/run.sh`，退出码 `0`。脚本从源码构建测试客户端和防火墙辅助程序，在一次性 Debian 12 容器内运行 SSH、systemd 和防火墙测试；Docker 需支持特权容器，镜像构建阶段需拉取系统依赖，测试阶段无外网。输出为：

```text
SSH probe and systemd, performance, interface, route and listener collection passed
Authorized SSH stop and start confirmed by systemd readback
UFW, nftables and iptables-legacy IPv4/IPv6 rules collected
SFTP upload, SSH stream fallback, staged command, idempotent maintenance and administrator verification passed
Firewall rules unchanged; systemd enabled before=enabled after=enabled, final state=active
```

最终候选包的更新与 kind 验证输出：

```text
Release check, HTTPS redirect, tamper rejection, verified staging and reuse passed
Manual Deployment collection passed; no-grant stop returned HTTP 403
stop: convergence=confirmed, state=stopped, desired=0, ready=0, resume=2
start: convergence=confirmed, state=running, desired=2, ready=2, resume=None
```

### 容量实测

使用最终 macOS amd64 包。三轮均成功，每轮快照实际存储行数与发布行数一致，没有叠加上轮的旧快照。

| 目标数 | 每轮成功／总数 | 每轮耗时（秒） | 每轮处理速率（目标／秒） | 排队 p95（毫秒） | API 批次 p95（毫秒） | 峰值并发 | 每轮快照行数 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 12 | 12／12 × 3 | 1.262 / 1.000 / 1.039 | 9.51 / 12.01 / 11.55 | 922 / 815 / 849 | 313 / 173 / 175 | 2 | 2,460 |
| 48 | 48／48 × 3 | 4.210 / 4.223 / 4.336 | 11.40 / 11.37 / 11.07 | 3,747 / 3,763 / 3,907 | 195 / 224 / 218 | 2 | 9,840 |

| 目标数 | 进程峰值 RSS（KiB） | 三轮 CPU 时间（秒） | SQLite 初始 → 最终（字节） | 各轮 SQLite 页数（每页 4,096 字节） |
| --- | --- | --- | --- | --- |
| 12 | 29,240 | 1.667 | 221,184 → 1,396,736 | 312 / 336 / 341 |
| 48 | 32,532 | 6.651 | 237,568 → 4,775,936 | 1,105 / 1,142 / 1,166 |
