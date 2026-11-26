# 01 · Imon V1 开发计划

对应方案：[01-v1-technical-solution.md](../solutions/01-v1-technical-solution.md)。本计划与方案文件同名、分目录，版本和编号同步。[V1 发布功能清单](../guides/v1-features.md)定义交付范围，[V1 界面草图](../design/v1-ui-wireframes.md)定义入口和交互，接口与运行规则以方案为准。保留本地客户端、三种防火墙后端、可配置轮询和手动采集，不设固定绑定数量上限。

实现状态见任务表；环境、构建产物和实测证据统一见 [V1 发布验证记录](../guides/v1-release-verification.md)。演示仅说明交互和接口行为，不是发布证据。路径相对项目根目录。演示共用合成对象 `h-demo`（主机 A）、`c-demo`（集群 A）、`demo`（命名空间）、`demo-web.service`（systemd 单元）和 `ns-demo-node-uid`（Node UID）。请求默认已建立本地面板会话，示例省略 HTTP 头和不相关的响应字段。

## 开发顺序

| ID | 任务名 | 开始所需的代码或契约 | 状态 |
| --- | --- | --- | --- |
| T01 | [本地客户端和存储](#t01-本地客户端和存储) | 无 | 已实现；macOS、Linux amd64 本地运行验证通过 |
| T02 | [主机管理、连接与解绑](#t02-主机管理连接与解绑) | T01 | 已实现；接口和浏览器联调 |
| T03 | [轮询、手动采集和任务](#t03-轮询手动采集和任务) | T01；T02 的目标版本契约 | 已实现；调度和任务回归 |
| T04 | [Linux 采集和主机页面](#t04-linux-采集和主机页面) | T02 SSH、T03 批次契约 | 已实现；解析与接口回归，Debian 12 主机链路实测 |
| T05 | [Kubernetes 采集和集群页面](#t05-kubernetes-采集和集群页面) | T02 API 连接、T03 批次契约 | 已实现；模拟 API 回归，隔离 kind 集群实测 |
| T06 | [防火墙读取与维护](#t06-防火墙读取与维护) | T02 SSH、T03 批次契约、T04 网络查询形状 | 已实现；Debian 12 上三种后端和授权流程实测 |
| T07 | [统一服务列表与启停](#t07-统一服务列表与启停) | T02 连接版本、T03 任务契约、T04 与 T05 的对象投影 | 已实现；隔离 systemd 和 kind Deployment 启停通过 |
| T08 | [告警规则与事件](#t08-告警规则与事件) | T01 事务、T02 生命周期、T03 批次契约；联调接入 T04、T05、T07 | 已实现；固定样本和面板流程验证 |
| T09 | [面板、Telegram 和邮件通知](#t09-面板telegram-和邮件通知) | T08 事件、未读与投递队列契约 | 已实现；模拟通知端通过，真实收件未验证 |
| T10 | [打包、恢复与发布验证](#t10-打包恢复与发布验证) | T01–T09、T11 的已验证构件 | 六个平台包构建及摘要通过；macOS、Linux amd64 解包运行；候选包未发布 |
| T11 | [侧栏版本与一键更新](#t11-侧栏版本与一键更新) | T01 本地 API 与数据目录、T10 的包名契约 | 本轮更新后重新验证 |

**发布功能覆盖：** F01 主机管理与采集 → T01–T03；F02 服务 → T04、T05、T07；F03 主机性能 → T04；F04 主机网络 → T04、T06；F05 Kubernetes 资源 → T05；F06 告警规则与事件 → T02、T03、T07、T08；F07 通知 → T08、T09；F08 版本和本地数据 → T10、T11。T11 可先用合成发布包开发，不等待 T10 的最终打包验收。

T02 先交付连接接口和版本约束，T03 可用假采集器开发。T04、T05 并行；T06 不等待整个主机页面完成，普通网络采集也不依赖防火墙维护权限。T07 的列表与任务逻辑可在假端开发，真实启停单独用隔离对象验证。T08 先跑固定样本并落实规则预填参数，T09 用合成事件开发；最终以真实链路联调为准。完成任务需保留演示、相关测试及未通过项记录。

## T01 本地客户端和存储

**来源与落点：** 方案 §1、§7.1、§9；新增 `cmd/imon/`、`internal/httpapi/`、`internal/store/`、`web/` 和存储测试。交付可启动的本地程序、嵌入面板入口、SQLite 迁移及后续任务共用的事务和数据模型。

**实施：** 先锁定私有数据目录并迁移 SQLite，再启动回环监听。实现一次性口令兑换、本地会话、Host/Origin 校验和嵌入式界面骨架。启动进入服务首页；侧栏包含「服务、主机管理、网络、告警」，底部的版本入口接 T11。菜单、标签和详情复用异步路由，只替换内容区域，迟到响应不得覆盖现有视图；统一表头工具栏、表单网格和控件高度。为后续模块提供单写入入口、只读查询及候选快照发布机制。在临时库构造绑定和快照记录，验证重启后可读。

**演示示例（CLI + 界面）：**

```text
$ ./imon
Panel URL: http://127.0.0.1:<PORT>/#<ONE_TIME_TOKEN>

+------------+--------------------------+
| > 服务     | Imon / 服务              |
|   主机管理 | 暂无服务  [前往主机管理] |
|   网络     |                          |
|   告警     |                          |
| [v1.0.0]   |                          |
+------------+--------------------------+
再次使用同一启动口令 → 会话兑换失败
用同一数据目录再启动一个实例 → 拒绝写入，不创建第二个写者
```

**完成判据：** 启动只监听回环；无会话访问受保护接口返回 401；Host/Origin 或令牌不合法的请求被拒绝；迁移报错保留原库证据且不启动采集；候选快照未发布时读不到部分结果。浏览器切换导航、前进后退及快速切换，核对没有整页重载、不显示过期响应；检查桌面及窄视窗中标签、输入框和按钮没有重叠。失败用临时库和本机请求定位，不更换数据库路线。

**实际验证：** macOS、Linux amd64 解包运行和 SQLite 回归已通过；其他打包目标不等同于运行验证，见 [发布验证记录](../guides/v1-release-verification.md)。

## T02 主机管理、连接与解绑

**来源与落点：** 方案 §2、§7.2；`internal/collector/ssh.go`、`internal/collector/kube.go`、`internal/control/{connection,query}.go`、`internal/httpapi/filepicker.go`、`internal/store/` 和 `web/`。交付 SSH 直连及单跳板、Kubernetes kubeconfig/Context、测试、绑定、编辑、手动节点关联、解绑及凭据引用管理。

**实施：** 两个连接适配器分别校验身份并执行最小只读探测。SSH 先使用已固定密钥或本机 `known_hosts`，未记录时确认握手返回的服务器指纹；已知密钥变更时拦截。系统选择窗口仅返回私钥路径，取消不覆盖输入；图形环境不可用时使用手填路径。测试票据绑定配置与已验证身份；保存复核。普通绑定不要求写权限。连接改动递增版本，改名不改版本。关联按 Node UID 一对一存储；解绑使旧批次不能再写入，取消排队、保留历史，对告警用 T08 的同事务停用逻辑。维护与启停进行中的解绑按方案 §2 处理。主机行的 [查看] 带目标进入 T04 机器性能，集群行进入 T05 资源详情；[创建告警] 预填目标。授权按钮接 T06，立即采集接 T03。

**演示示例（界面 + API）：**

```text
主机管理  [*主机*] [Kubernetes 集群]  [绑定主机] [绑定集群] [采集设置]
名称    SSH 状态  CPU  内存  磁盘  最近成功  操作
主机 A  成功      24%  58%   92%   12:40:00  [查看] [编辑] [解绑] [安装授权] [创建告警]
[查看] → 主机 A / 机器性能；集群行 [查看] → 集群 A / 资源详情
绑定主机：地址 [<SSH_ADDRESS>]  SSH 私钥路径 [<SSH_KEY_REF>]  [选择文件]  [测试连接]
首次连接且本地未登记：SHA256:<FINGERPRINT>  [确认指纹并测试]
测试通过；防火墙未授权，不影响保存。  [保存绑定]
```

```http
POST /api/v1/local/file-picker

200 OK
{"path":"<SSH_KEY_REF>"}

POST /api/v1/targets/test
{"kind":"host","ssh":{"address":"<SSH_ADDRESS>","port":22,"user":"<SSH_USER>","key_file":"<SSH_KEY_REF>"}}

409 Conflict
{"code":"host_key_confirmation_required","details":{"role":"target","address":"<SSH_ADDRESS>:22","fingerprint":"SHA256:<FINGERPRINT>","confirmation_token":"<CONFIRMATION_TICKET>"}}

POST /api/v1/targets/test
{"kind":"host","ssh":{"address":"<SSH_ADDRESS>","port":22,"user":"<SSH_USER>","key_file":"<SSH_KEY_REF>"},"ssh_confirmation_token":"<CONFIRMATION_TICKET>"}

200 OK
{"test_token":"<SHORT_LIVED_TICKET>","warnings":["firewall_unreadable"]}

POST /api/v1/targets
{"kind":"host","name":"主机 A","ssh":{"address":"<SSH_ADDRESS>","port":22,"user":"<SSH_USER>","key_file":"<SSH_KEY_REF>"},"test_token":"<SHORT_LIVED_TICKET>"}

201 Created
{"id":"h-demo","connection_rev":1}

GET /api/v1/targets/h-demo

200 OK
{"id":"h-demo","connection_rev":1,"config":{"ssh":{"address":"<SSH_ADDRESS>","port":22,"user":"<SSH_USER>","key_file":"<SSH_KEY_REF>"}}}
```

**完成判据：** 用隔离 SSH 假端核对已有主机直接通过、未记录的主机先提示指纹、已确认密钥被更换时拦截、两跳独立核验及测试改参失效。分别验证选中回填、取消不改输入，以及对话框失败后手填；响应不输出凭据内容。继续验证未明确授权的插件拒绝、[查看] 和 [创建告警] 带入当前目标、Node 同名重建不复用关联、解绑集群后主机仍独立采集。实机缺认证、通路或图形会话时，记录证据并只保留对应实机构建待验证。

## T03 轮询、手动采集和任务

**来源与落点：** 方案 §3、§7；`internal/control/scheduler.go`、`internal/store/` 和 `web/`。交付可关停/改周期的轮询、按目标或分项手动采集、任务状态及可控排队。

**实施：** 用可控时钟先测每目标串行、分项合并、计划与手动来源、工作池配额、设置版本、取消和退避，再接真实采集器。为超时和未执行分别返回分项结果，不将队列积压认作失联；收集目标数不限，执行并发有界。重启清除运行态，不补排错过的轮次。

**演示示例（界面 + API）：**

```text
主机管理 / 采集设置
[ ] 开启轮询   性能/服务 [60] 秒   网络 [300] 秒   集群 [60] 秒   [保存]
主机 A  自动采集已关闭   [立即采集]   任务：排队 → 执行中 → 部分成功
```

```http
PUT /api/v1/sampling-settings
{"poll_enabled":false,"host_interval":60,"network_interval":300,"cluster_interval":60,"timeout":45}

200 OK
{"poll_enabled":false,"revision":2}

POST /api/v1/targets/h-demo/collect
{"groups":["host_metrics","firewall"]}

202 Accepted
{"job_id":"job-demo"}

GET /api/v1/jobs/job-demo

200 OK
{"status":"partial","results":{"host_metrics":"","firewall":"firewall_unreadable"}}
```

**完成判据：** 关闭轮询后无自动任务，仍能手动采集；重复点击覆盖中的分项不会多发任务；同时等待时不饿死自动任务；压入超出并发槽数的绑定仍可保存，停止或休眠不生成失联。失败优先用时钟和假采集器复现，保留任务来源、设置版本和去重键。

## T04 Linux 采集和主机页面

**来源与落点：** 方案 §4、§7.2；`internal/collector/{ssh,linux}.go`、`internal/control/{scheduler,query}.go`、`internal/store/` 和 `web/`。交付 CPU、内存、磁盘、网卡趋势，systemd 服务快照，以及接口、路由、监听端口的分项快照和页面。防火墙由 T06 实现。

**实施：** 固定命令分项读取，文档化输出样本及错误；实现 boot ID/ifindex 差分、每挂载点/接口历史与过期状态。读路径只查 SQLite，支持历史区间和分页。一级「网络」先选主机，机器性能页可直接跳到同一主机的网络详情，网络详情可返回机器性能。监听端口表无「操作」列；从磁盘行生成 T08 使用的规则预填参数。

**演示示例（界面 + API）：** 同 boot ID、同 ifindex 的 60 秒样本，CPU 总时钟增量 1000、idle+iowait 增量 760 → 24%；网卡接收增量 60 MiB → 1 MiB/s。

```text
主机详情 / 机器性能  [主机 A v]  [最近 1 小时 v]  [立即采集] [网络详情]
CPU 24%  /\__     内存 58%  ___/--
磁盘 /   92 / 100 GiB  92%  [创建告警]
网卡 <IFACE>   RX 1 MiB/s   TX 0.4 MiB/s

主机详情 / 网络（只读） [主机 A v]  [接口] [路由] [*监听端口*] [防火墙] [机器性能]
协议  地址         端口  进程
TCP   192.0.2.10   8080  不可读
```

```http
GET /api/v1/hosts/h-demo/network/listeners

200 OK
{"attempt":{"status":"ok"},"items":[{"object_key":"tcp|ipv4|192.0.2.10|8080","payload":{"protocol":"tcp","family":"ipv4","address":"192.0.2.10","port":8080,"process_state":"unreadable"}}]}

GET /api/v1/hosts/h-demo/metrics?from=<FROM_UTC_MS>&to=<TO_UTC_MS>

200 OK
{"items":[{"object_key":"cpu","payload":{"cpu_percent":24}}],"history":[{"metric":"cpu_percent","dimension":"","at":60000,"value":24,"max":24}]}
```

**完成判据：** 差分重置、磁盘口径、网络双栈、空结果、分项失败和进程缺权分别通过样本测试；失败留前次有效值和时间，趋势缺口不用 0 装填。真实 Linux 缺命令时记录具体分项为不可用，其余照常验证；不临时换成 Agent。

## T05 Kubernetes 采集和集群页面

**来源与落点：** 方案 §6、§7.2；`internal/collector/{kube,kube_service}.go`、`internal/control/query.go`、`internal/store/` 和 `web/`。交付 Namespace、Deployment、Pod、Service、Node 列表及筛选，EndpointSlice 派生数据、节点关联和资源告警入口。

**实施：** 从正式连接获取只读客户端；按类型分页读取并汇集精简行，完整读取后分批写入本地候选代，再一次发布。处理 410、403 和超时。解析 readiness、generation、删除状态，按同轮完整输入汇总；EndpointSlice 按 Pod UID 去重。不把 Node 放进命名空间过滤，不给 Service 增加工作负载告警。

**演示示例（界面 + API）：** 两个 EndpointSlice 各出现一次同 UID 后端，另外一个端点正在终止，最终就绪后端数为 1。

```text
集群详情 [集群 A v]   API 正常  [立即采集] [主机管理]
[命名空间] [部署] [Pod] [*服务*] [节点]   命名空间 [demo v]
名称       类型       端口    就绪后端
demo-web   ClusterIP  80/TCP  1
EndpointSlice 权限撤销后 → 就绪后端：未知（不可读）
```

```http
GET /api/v1/clusters/c-demo/resources/services?namespace=demo

200 OK
{"items":[{"object_key":"demo-service-uid","payload":{"name":"demo-web","namespace":"demo","ready_backends":1,"backends_state":"ok"}}]}

GET /api/v1/clusters/c-demo/resources/services?namespace=demo

200 OK
{"items":[{"object_key":"demo-service-uid","payload":{"name":"demo-web","namespace":"demo","ready_backends":null,"backends_state":"unreadable"}}]}
```

**完成判据：** 缺权、分页中断、真空列表、缩容为零及对象同名重建用合成响应验证；只读身份只能访问方案规定的资源；失联与后续分项失败能区分。集群无 EndpointSlice v1 时保留资源浏览，明确后端数不支持；保留返回码和分项结果，不把旧后端显示成新采样。

## T06 防火墙读取与维护

**来源与落点：** 方案 §5、§7.2；`cmd/imon-firewall/`、`internal/firewall/`、`internal/collector/maintenance.go`、`internal/control/firewall.go` 和 `web/`。交付独立只读读取器、三种后端、安装/卸载、管理员接管与重检测。

**实施：** 按 UFW 管理视图、nftables、legacy IPv4/IPv6 分开解析及记录失败。按方案制作受管维护包：已授权管理员用校验后的受保护暂存安装或卸载；普通账号没有提权时只上传、展示摘要及管理员命令，不自动执行。分别验证受管文件与普通采集调用；SSH 中断记为待核实，成功安装不意味着所有后端都可读。

**演示示例（界面 + API）：**

```text
主机管理 / 主机 A   [安装授权]
读取器：待管理员操作（暂存成功）  [查看命令与校验摘要]
管理员按方案 §5.3 执行后，点 [重新检测]；验证卸载时提供独立管理员凭据
读取器：已安装  [卸载授权]

主机 A / 网络（只读） / 防火墙
UFW：未启用      nftables：成功，无规则
legacy IPv4：成功，2 条     legacy IPv6：未检测到工具
```

```http
POST /api/v1/hosts/h-demo/firewall-maintenance
{"action":"install"}

202 Accepted
{"job_id":"fw-demo"}

GET /api/v1/jobs/fw-demo

200 OK
{"status":"awaiting_admin","stage_path":"<STAGED_SCRIPT>","sha256":"<SHA256_FROM_TRUSTED_CLIENT>","command":"<ADMIN_COMMAND>"}
```

**完成判据：** 在获授权的隔离环境验证三种后端及混用、普通读取权限、不修改规则、重复安装/卸载及撤权后不可调用。主机管理行在探测确认后切换授权按钮；无自动管理员权限只产生暂存和接管指引；上传失败保留导出入口；中断后未确认状态不显示已安装或已卸载。权限/架构不符只阻断对应部署验证，其他网络分项保持可用。

## T07 统一服务列表与启停

**来源与落点：** 方案 §4、§6、§7.1–§7.3；`internal/control/services.go`、`internal/collector/action.go`、`internal/store/` 和 `web/`。交付 systemd 与 Deployment 统一列表、状态与位置筛选、启停授权及任务、告警预填。Kubernetes Service、Pod 原始状态留在集群详情，不纳入启停。

**实施：**

1. 将采集结果投影为「运行中／失败／停止／启动中」，同时保留独立的采集状态和时间；无根据的未知或过期不显示为服务失败，也不据此允许写操作。运行中提供 [停止]，停止或失败提供 [启动]，启动中不允许重复操作；失败但期望副本仍大于零的 Deployment 禁用 [启动] 并提示查看集群详情。[创建告警] 带入对象身份。
2. 启停须显式启用并经用户确认。任务绑定目标版本、对象身份及动作；按对象串行，用同一任务查询跟踪远端结果。只读绑定仍可浏览并创建告警。预检失败不发送写请求；远端结果不明时不自动重做，先核实并刷新，操作者确认后才提交 `confirm_unknown:true`。复核与刷新不依赖自动轮询。
3. systemd 用单独授权的凭据对明确允许的单个单元发起操作，不影响开机策略；按实际读回状态更新列表。Deployment 仅针对明确授权、独立手动管理的对象，通过 Scale 子资源修改副本数；写前核对 UID 和版本。停止前持久保存原正副本数，缩容为零；后续启动恢复该值，缺记录时请求用户明确指定副本数。检测到 HPA 或已知外部控制时拒绝启停，不接管控制权。操作执行结果与工作负载达到目标状态分开呈现。

**演示示例（界面 + API）：**

```text
服务     [*全部*] [宿主机] [Kubernetes]   搜索 [demo-web]
名称               来源         类型          位置          状态     操作
demo-web.service   宿主机       systemd       主机 A        运行中   [停止] [创建告警]
demo-web           Kubernetes   Deployment    集群 A/demo   停止     [启动] [创建告警]
启动 demo-web / 恢复副本数：2    [取消] [确认启动]
目标副本数已写入并读回 → 等待副本达标 → 已确认达到目标状态
```

```http
PUT /api/v1/targets/c-demo/service-authorization
{"connection_rev":1,"credential_ref":{"kubeconfig":"<KUBE_OPERATOR_REF>","context":"<OPERATOR_CONTEXT>"},"object_ids":["svc-demo-deploy"],"external_manager_checked":true}

204 No Content

GET /api/v1/services?q=demo-web&source=kubernetes&cluster_id=c-demo&namespace=demo

200 OK
{"items":[{"id":"svc-demo-deploy","source":"kubernetes","state":"stopped","ready":0,"desired":0,"resume_replicas":2}],"next_cursor":null}

POST /api/v1/services/svc-demo-deploy/actions
{"action":"start","connection_rev":1,"expected_state":"stopped","expected_desired":0}

202 Accepted
{"job_id":"svc-job-demo"}

GET /api/v1/jobs/svc-job-demo

200 OK
{"status":"success","results":{"convergence":"pending"}}
```

**完成判据：** 组合筛选、稳定分页、同名对象区分、空列表与采集失败分别呈现；验证只读不可启停、同一对象重复点击、确认后的状态变化、版本失效、同名重建、结果待核实、HPA 拒绝与初始零副本。用获授权的隔离单元和 Deployment 做启停往返，核对 systemd 开机设置不变，Deployment 从 2 → 0 → 2，并在关闭轮询时验证读回及分项刷新。缺写权限或不能确认工作负载独立管理时继续验证列表、告警预填和假端任务，不报告真实启停通过。

## T08 告警规则与事件

**来源与落点：** 方案 §3、§7、§8.1；新增 `internal/alert/`，接入 `internal/store/` 采集提交、`internal/httpapi/` 规则和事件、`web/` 事件列表、独立详情及规则编辑器。交付可配置阈值、状态、持续时间或连续次数的规则，和从列表到详情到数据来源的查询流程。

**实施：** 先用固定批次编写状态机及持久化测试，再接入 Linux、Kubernetes 和连接探测；验证各页预填对象选择器、单位和条件组合。快照发布、规则评估、事件及投递登记同事务提交。规则只消费新的有效观察；关轮询后非零持续规则不新触发，手动样本仍可确认恢复。点击一级「告警」默认进入事件列表，按触发时间倒序，提供全部、活动、已恢复、未读筛选；「监控停止」和「配置变更」仅在全部状态中出现。详情展示触发条件、最新值、触发与恢复时间及投递结果；返回保留筛选，解绑的来源保留名称快照且不跳向同名新对象。未读列及计数与 T09 联调。

**演示示例（界面 + API + 样本）：**

```text
告警   [*事件*] [规则] [通知渠道]  [新建规则]
[*全部*] [活动] [已恢复] [未读]
面板  级别  告警规则      对象        状态  触发   恢复  操作
--    警告  磁盘空间不足  主机 A / <挂载点>  活动  12:38  --  [查看]

告警 / 事件详情                               [返回事件列表]
磁盘空间不足  警告  主机 A / <挂载点>  活动
条件：磁盘使用率 > 90%，连续 2 次  最新值：93%
触发：12:38  恢复：--  投递：无实际投递  [回到数据来源]

告警   [事件] [*规则*] [通知渠道]  [新建规则]
对象 [主机 A / <挂载点>]  指标 [磁盘使用率]  条件 [>] [90] %
触发 [连续 2 次]  级别 [警告]  面板 [ ]  Telegram [ ]  邮箱 [ ]  [保存并启用]
```

```http
POST /api/v1/alert-rules
{"name":"磁盘空间不足","enabled":true,"severity":"warning","selector":{"target_id":"h-demo","metric":"disk_usage_percent","mountpoint":"/"},"condition":{"op":"gt","value":90},"trigger":{"consecutive_samples":2},"channels":{"panel":false,"telegram":false,"email":false}}

201 Created
{"id":"rule-demo","enabled":true}

GET /api/v1/alert-events?status=active

200 OK
{"items":[{"id":"event-demo","rule_id":"rule-demo","status":"active","latest_value":93}],"unread_count":0,"next_cursor":null}

GET /api/v1/alert-events/event-demo

200 OK
{"id":"event-demo","status":"active","latest_value":93,"recovered_at":null,"panel_revision":0}
```

轮询开启，用 T03 的 60 秒周期回放：

| 批次 | 磁盘结果 | 预期事件 |
| --- | --- | --- |
| B1 | 92%，本轮完整 | 待触发，累计 1 次 |
| B2 | 93%，本轮完整 | 活动告警，记录 1 条事件，通知数 0 |
| B2 重放 | 93%，相同批次 | 不新增或再次触发 |
| B3 | 超时，缓存仍是 93% | 保留活动，不判恢复 |
| B4 | 87%，本轮完整 | 原事件恢复，不另建活动事件 |

**完成判据：** 回放覆盖端口明确缺失与快照失败、权限不足、配置变更、失联退避、手动及计划、重启和解绑；旧设置版本或已解绑目标不推进规则，状态转移不产生重复事件。事件排序、状态筛选、空结果、详情、返回和失效来源按样本测试。失败用批次、规则状态与事件 ID 定位，不接真实外部通知。

## T09 面板、Telegram 和邮件通知

**来源与落点：** 方案 §7.2、§8.2；`internal/alert/{notify,transport,http}.go`、`internal/store/`、`web/` 通知配置及事件详情。交付每渠道全局开关、每规则渠道选择、测试、触发/恢复投递及持久化结果。

**实施：** 先实现全局启用与规则选择的交集，再接入事件生成的阶段投递记录。面板通知在事件列表标记未读；列表返回全部事件范围内的未读计数，打开详情后提交实际读到的通知版本，重放已读请求不覆盖后来生成的通知。测试通知不新增事件或未读数。Telegram、SMTP 先用测试端验证已受理、明确失败、限流及回执未知，再在事件事务外投递。同一目的地触发先于恢复，不自动重发不确定结果。

**演示示例（界面 + API）：**

```text
告警   [事件] [规则] [*通知渠道*]
渠道       启用  配置
面板通知   [x]   在事件列表标记未读
Telegram   [x]   接收目标 [演示目标 v]  凭据 [<CREDENTIAL_REF>]
邮箱       [ ]   收件人 [<RECIPIENT>]  凭据 [<CREDENTIAL_REF>]
[保存] [发送测试通知]
测试结果：已受理；面板未读计数不变。

告警 (1) / 事件详情 event-notify-demo
面板：已投递，未读  |  Telegram：已受理  |  邮箱：未启用
打开详情并标记已读：未读数 1 → 0；事件仍保留。
```

```http
PUT /api/v1/notification-settings
{"panel":true,"telegram":true,"email":false}

200 OK
{"panel":true,"telegram":true,"email":false}

POST /api/v1/notification-targets/notify-demo/test

200 OK
{"channel":"telegram","result":"accepted","test":true}

GET /api/v1/alert-events?unread=true

200 OK
{"unread_count":1,"items":[{"id":"event-notify-demo","status":"active"}],"next_cursor":null}

GET /api/v1/alert-events/event-notify-demo

200 OK
{"id":"event-notify-demo","panel_revision":1,"panel_read_revision":0}

POST /api/v1/alert-events/event-notify-demo/read
{"through_revision":1}

200 OK
{"id":"event-notify-demo","unread_count":0}
```

**完成判据：** 验证全局关闭或规则未选中均不生成该渠道投递，三关只记事件，重新开启不为旧事件补发；测试不增加业务事件或未读；翻页和筛选不更改菜单计数，旧详情不能清除刚到的恢复未读。验证重试、TLS/代理失败、配置变更不改目的地、发送中重启和回执未知时不重发。实机 Telegram/SMTP 不通时记录对应测试结果并检查现有网络路径，不安装额外中转，也不阻断面板与事件验证。

## T10 打包、恢复与发布验证

**来源与落点：** 方案 §1、§5、§7.1、§9；`packaging/release/`、`internal/store/backup_restore.go` 及 `docs/guides/` 的安装、启动和数据备份恢复说明。汇集 T01–T09 与 T11 的验证记录。

**实施：** 构建目标平台的客户端与适用架构的 Linux 读取器，校验内嵌版本及摘要；在各平台实际启动并验证保存、重启、备份恢复。按 F01–F08 核对「绑定 → 手动采集 → 查询 → 授权启停 → 创建规则 → 告警默认事件列表 → 详情与已读 → 解绑」，另验授权安装/卸载、独立渠道配置、适用平台的一键更新和启动失败回退。复用适用于当版构建的任务证据；统计不同目标数下的队列延迟、CPU、RSS 和 SQLite 增长，记录平台/网络/采集周期。

**演示示例（CLI + 端到端检查输出）：** 在测试平台启动对应产物，使用隔离目标和假通知服务；以下日志是演示判定，不是实测。

```text
$ ./imon
Panel URL: http://127.0.0.1:<PORT>/#<ONE_TIME_TOKEN>

手动采集   主机 A；轮询关闭；任务成功且有本地快照
授权验证   防火墙读取器安装后可读，卸载后不可读，规则不变
服务启停   隔离 systemd 单元停止后恢复；独立 Deployment 副本 2 → 0 → 2
告警闭环   活动事件 → 默认事件列表 → 详情已读 → 原事件确认恢复
重新启动   h-demo、c-demo 仍可查询，未补跑停机期间的轮次
备份恢复   恢复到隔离数据目录；历史事件可查询；凭据独立提供
一键更新   侧栏出现新版本提示；点击后校验安装、自动重连；历史仍可查询
解绑集群   删除节点关联；主机仍可手动采集；历史事件仍在
资源验证   绑定数=<COUNT>，并发峰值=<PEAK_WORKERS>，排队延迟=<QUEUE_MS>
```

**完成判据：** 正式声明的平台有当版启动、采集、保存与重启记录；从备份恢复后历史可查；防火墙、告警和通知有闭环证据。未通过平台不标成已支持；发现回归回到对应任务修复并重验相关链路。没有容量实测时不发布吞吐或资源承诺。

## T11 侧栏版本与一键更新

**来源与落点：** 方案 §7.2、§10；`internal/update/`、`internal/httpapi/`、`cmd/imon/`、`packaging/release/` 和 `web/`。交付侧栏版本号、启动自动检查一次、红点、带发布链接的气泡，以及适用平台的一键更新。

**实施：** 构建时可预设仓库，运行时可用 `--release-repo <OWNER>/<REPO>` 指定；无公网访问只影响检查和下载，不影响监控。首次打开后检查匹配正式包；侧栏气泡根据 `can_apply` 展示更新按钮或发布页链接。点击更新后独立验证包、备份 SQLite、原地替换程序并使用相同端口重启；原浏览器凭本地会话查询运行版本，从而确认安装或回退。

**演示示例（界面 + API）：**

```text
侧栏底部 [v1.0.0] * → 打开气泡
新版本 v1.1.0   <发布说明>    [GitHub 发布页] [更新]
更新中 → 等待客户端重启 → [v1.1.0]
启动失败并回退 → [v1.0.0]  显示回退结果
```

```http
GET /api/v1/version

200 OK
{"current":"v1.0.0","repository":"<OWNER>/<REPO>","state":"configured"}

GET /api/v1/version/update?startup=1

200 OK
{"state":"available","tag":"v1.1.0","asset_name":"imon-web_linux_amd64.tar.gz","sha256":"<ARCHIVE_SHA256>","release_url":"<GITHUB_RELEASE_URL>","can_apply":true}

POST /api/v1/version/update/apply
{"tag":"v1.1.0","sha256":"<ARCHIVE_SHA256>"}

202 Accepted
{"state":"restarting"}
```

**完成判据：** 同一进程只查一次；切换和打开气泡不重复查询。有新版本时出现红点、发布页链接及适用的更新按钮，无新版本时不出现红点。仓库发布变化、摘要不符或下载中断时不安装；使用隔离副本和合成 Release 验证真正重启、会话及数据保留，以及新版本启动失败后回退。公开仓库实际下载和未验证的平台单独记录。

## 实机配合

| 任务 | 所需条件 | 条件暂缺时继续做什么 |
| --- | --- | --- |
| T02、T04、T05 | 可达的测试 Linux+systemd、SSH 登录权限及可独立核对的服务器指纹；测试集群的专用只读权限和通路 | 用合成数据和假端推进接口、解析及 UI；对应实机用例保持待验证 |
| T06 | 隔离 Linux 测试机、明确授权的管理员和普通采集账号、目标防火墙后端 | 继续验证解析、暂存流程和错误呈现；不能把未经验证的安装/卸载状态标为已完成 |
| T07 | 可停启的隔离 systemd 测试单元、明确仅对该单元的操作授权；独立手动管理的测试 Deployment 和仅对该对象的 Scale 权限 | 用假端验证任务、冲突和过期处理；真实写操作缺授权时只联调只读路径，留存失败响应及对应目标的未验证状态 |
| T09 | 可控 Telegram/SMTP 测试端；如需实发，操作者设置测试接收目标及出口 | 假端覆盖投递状态及重试；面板和事件可独立验证 |
| T10 | 发布目标平台或等效运行环境、代表性测试规模 | 已通过平台继续保留证据；未验证平台与性能数字不写成发布事实 |
| T11 | 已发布正式版本且有匹配平台包和摘要的公开 GitHub 仓库 | 用合成 Release 和实际隔离可执行文件回归检查、校验、重启及回退；不代替公开仓库实测 |
