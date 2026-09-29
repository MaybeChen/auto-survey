# API Survey AI

跨平台的 HTTP/1.1 流量接口调研 V1。dumpcap 只负责抓包，tshark 负责协议解析；共享的 Python 核心完成确定性关联、解码、脱敏、聚类、证据验证和事实层输出，AI 仅增强语义。

## 架构与范围

`dumpcap → pcap/pcapng → tshark → Transaction → Decoder → Redaction → Endpoint → AI → Validator → Standard Interface JSON → Catalog/OpenAPI`。V1 支持 IPv4/TCP/HTTP/1.1 JSON；不破解 TLS，不支持 QUIC、HTTP/3、gRPC、WebSocket 或 multipart 内容分析。仅有 TLS 的文件标记为 `BLOCKED_TLS`；未来可在 tshark 边界增加用户提供的 SSLKEYLOGFILE。

## 安装

需要 Python 3.11+、tshark 和 dumpcap。

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
cp config/config.example.yaml config.yaml
```

### Windows 10/11/Server

以下命令均在项目根目录执行。建议将项目放在不会被移动的固定位置，例如 `C:\api-survey-ai`；计划任务会保存脚本的绝对路径。

#### 1. 安装基础软件

1. 安装 **64 位 Python 3.11 或更高版本**。安装器中勾选 **Add python.exe to PATH**，然后在新的 PowerShell 窗口确认：

   ```powershell
   python --version
   ```

2. 从 Wireshark 下载页选择安装包：绝大多数采用 Intel 或 AMD CPU 的 Windows 10/11/Server 电脑请选择 **Windows x64 Installer**；只有“系统类型”明确显示 ARM64（例如部分 Snapdragon Windows 设备）时才选择 **Windows Arm64 Installer**。不要选择 **Windows x64 PortableApps**，因为便携版不适合安装 Npcap 驱动和部署无人值守计划任务。可在“设置 → 系统 → 系统信息 → 系统类型”确认架构，或执行 `$env:PROCESSOR_ARCHITECTURE`（`AMD64` 选择 x64，`ARM64` 选择 Arm64）。安装 Wireshark 时，组件选择页面保留 **TShark**。**并非所有安装场景都会显示 Npcap 页面**：安装器检测到已有兼容 Npcap 时可能跳过；Microsoft Store/便携版、组织重新打包的软件或某些离线安装包也可能不捆绑 Npcap。Npcap 有时会以独立的子安装程序窗口出现，而不是 Wireshark 的“组件”复选框。
3. 在“应用和功能”或“已安装的应用”中检查是否存在 **Npcap**。也可以在 PowerShell 中检查服务：

   ```powershell
   Get-Service npcap -ErrorAction SilentlyContinue
   Test-Path "$env:SystemRoot\System32\Npcap\wpcap.dll"
   ```

   如果两项都没有结果，应从 **Npcap 官方网站**单独下载安装，然后重启 Windows。不要仅安装旧版 WinPcap；本项目在 Windows 10/11/Server 上使用 Npcap。企业电脑若无法安装，需让管理员允许 Npcap 驱动安装。

   Npcap 的 **Installation Options** 页面建议按下表选择：

   | 选项 | 默认建议 | 说明 |
   | --- | --- | --- |
   | Restrict Npcap driver's access to Administrators only | **不勾选** | 最容易完成首次验证；勾选后普通 PowerShell 不能抓包，必须使用管理员进程。生产环境若要求最小权限可以勾选，本项目的 `SYSTEM` 计划任务仍可抓包。 |
   | Support raw 802.11 traffic (and monitor mode) for wireless adapters | **不勾选** | 普通 Wi-Fi 上网流量不需要；只有明确需要 Wi-Fi Monitor Mode、原始 802.11 帧时才勾选。 |
   | Install Npcap in WinPcap API-compatible Mode | **不勾选** | Wireshark、TShark 和 dumpcap 原生支持 Npcap；仅遗留程序只能识别 WinPcap 时才使用，该选项还可能替换已有 WinPcap。 |

   因此，本项目首次安装可保持截图中的三个选项**全部不勾选**，直接点击 **Install**。若这是受管控的生产服务器，可勾选第一项加强权限，但后续手工执行 `dumpcap -D` 和抓包测试时要使用管理员 PowerShell。不要为了抓普通 Wi-Fi HTTP 流量而勾选第二项。
4. 安装完成后关闭并重新打开 PowerShell，验证工具。程序先查找 `PATH`，找不到时再查找 `C:\Program Files\Wireshark`：

   ```powershell
   & 'C:\Program Files\Wireshark\tshark.exe' --version
   & 'C:\Program Files\Wireshark\dumpcap.exe' --version
   & 'C:\Program Files\Wireshark\dumpcap.exe' -D
   ```

   `dumpcap -D` 会输出接口编号和名称，例如 `1. \Device\NPF_{...} (Ethernet)`。记录要抓取的接口编号。只要该命令能够正常列出接口，Npcap 就已经可供 dumpcap 使用，即使安装 Wireshark 时没有看见 Npcap 页面。若 `tshark`/`dumpcap` 存在但 `dumpcap -D` 不显示接口或提示找不到捕获驱动，再单独修复或安装 Npcap，并检查 `npcap` 服务。

   如果 Wireshark 安装在非默认目录，例如 `D:\Wireshark`，请改用 `& 'D:\Wireshark\tshark.exe' --version` 和 `& 'D:\Wireshark\dumpcap.exe' -D` 验证，并在 `config.yaml` 中显式设置：

   ```yaml
   tshark:
     path: "D:/Wireshark/tshark.exe"
   dumpcap:
     path: "D:/Wireshark/dumpcap.exe"
   ```

   YAML 中推荐使用正斜杠。`analyze`、Capture Service、`list-interfaces` 和 `doctor` 都会优先使用显式配置的工具路径，无需修改系统 `PATH`。

#### 2. 安装 Python 程序

普通 PowerShell 即可执行安装脚本。若系统执行策略阻止本地脚本，只对本次进程临时放行：

```powershell
cd C:\api-survey-ai
Set-ExecutionPolicy -Scope Process Bypass
.\deploy\windows\install.ps1
```

脚本会创建 `.venv`、安装当前项目、创建 `logs`，并在不存在时将 `config/config.windows.example.yaml` 复制为 `config.yaml`。它不会覆盖已有配置。

如果执行 `api-survey --help` 报告 `ModuleNotFoundError: No module named 'src'`，说明虚拟环境安装的是早期未包含 Python 包的构建。请在项目根目录修复安装：

```powershell
.\.venv\Scripts\python.exe -m pip install --force-reinstall --no-deps .
.\.venv\Scripts\api-survey.exe --help
```

不要只复制 `api-survey.exe`；控制台入口和 `src` Python 包必须由同一次 `pip install` 安装。

如果 `check-ai` 提示 `invalid choice`，说明 `.venv` 里仍是增加该命令之前安装的旧版本，
而不是模型配置错误。拉取最新代码后，在项目根目录强制重装，并确认帮助中出现命令：

```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade --force-reinstall .
.\.venv\Scripts\api-survey.exe --help | Select-String "check-ai"
.\.venv\Scripts\api-survey.exe --config .\config.yaml check-ai
```

也可以重新运行 `deploy/windows/install.ps1`；脚本现在会强制更新当前项目，并在安装结果
缺少 `check-ai` 时直接报错。重装 Python 包不会覆盖现有的 `config.yaml`、抓包文件、
SQLite 数据库或 `storage.root` 下的输出。

#### 3. 配置数据目录和抓包接口

编辑项目根目录的 `config.yaml`，至少修改以下项目：

```yaml
storage:
  root: "D:/api-survey-ai-data"   # SYSTEM 账户必须有写权限
capture:
  backend: "dumpcap"
  interface: "1"                 # 使用 dumpcap -D 显示的编号或设备名
  filter: "tcp port 80"          # 空字符串表示不过滤；V1 只能分析明文 HTTP
```

路径推荐使用正斜杠。确认数据盘有足够空间；默认轮转上限约为 `filesize_kb × files`。如启用 AI，API Key 不能写进 YAML，应设置为机器级环境变量，以便 `SYSTEM` 计划任务读取：

```powershell
[Environment]::SetEnvironmentVariable('AI_API_KEY', '实际密钥', 'Machine')
```

设置后需重启计划任务。命令会把密钥保存在 Windows 机器级环境中；应按组织的凭据管理要求保护该主机。AI 默认关闭，不配置密钥也能生成基础接口事实层。

#### 4. 安装前手工验证

先确认适配器能列出接口，再分别进行短时间抓包和分析验证：

```powershell
.\.venv\Scripts\api-survey.exe --config config.yaml list-interfaces
.\.venv\Scripts\python.exe -m src.capture_service --config config.yaml
```

第二条命令会持续抓包并按配置轮转；访问一个明文 HTTP 服务产生测试流量，等待生成 pcapng 后按 `Ctrl+C` 停止。然后启动监听分析器：

```powershell
.\.venv\Scripts\api-survey.exe --config config.yaml watch
```

watch 只处理已稳定的文件，默认需等待文件停止修改 20 秒并连续两次大小一致。可按 `Ctrl+C` 停止，并检查：

```text
D:/api-survey-ai-data/output/reports/analysis-summary.json
D:/api-survey-ai-data/output/api-catalog.json
D:/api-survey-ai-data/output/interfaces/
D:/api-survey-ai-data/output/openapi/
```

#### 5. 注册无人值守计划任务

以**管理员身份**打开 PowerShell，进入项目目录后执行：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\deploy\windows\install_task.ps1
```

脚本创建并立即启动以下任务：

* **API Survey Capture**：以 `SYSTEM` 身份运行 `src.capture_service`，启动 dumpcap 并把轮转文件写入 `capture/incoming`。
* **API Survey Agent**：以 `SYSTEM` 身份运行 `api-survey watch`，等待稳定文件并执行分析。

两个任务均在系统启动时触发，失败后每分钟重试，最多 100 次，并启用 `StartWhenAvailable`。项目目录和 `storage.root` 不能依赖某个登录用户的映射网络盘；服务场景应使用本地盘或授予 `SYSTEM` 权限的 UNC 路径。

#### 6. 检查、重启和卸载任务

```powershell
Get-ScheduledTask -TaskName 'API Survey *' | Format-Table TaskName, State
Get-ScheduledTaskInfo -TaskName 'API Survey Capture'
Get-ScheduledTaskInfo -TaskName 'API Survey Agent'
Get-Content .\logs\capture.log -Tail 100
Get-Content .\logs\agent.log -Tail 100

Stop-ScheduledTask -TaskName 'API Survey Capture'
Start-ScheduledTask -TaskName 'API Survey Capture'
Stop-ScheduledTask -TaskName 'API Survey Agent'
Start-ScheduledTask -TaskName 'API Survey Agent'

Unregister-ScheduledTask -TaskName 'API Survey Capture' -Confirm:$false
Unregister-ScheduledTask -TaskName 'API Survey Agent' -Confirm:$false
```

修改 `config.yaml` 或机器级 AI 环境变量后，应重启两个任务。`LastTaskResult = 0` 表示上次正常退出；非零时优先查看 `logs/capture.log`、`logs/agent.log` 和 Windows 任务计划程序历史记录。常见问题包括接口编号变化、Npcap 未运行、`SYSTEM` 对数据目录无写权限、磁盘空间不足，以及流量实际为 HTTPS（此时 V1 会标记 `BLOCKED_TLS`，不会尝试破解）。

### Ubuntu/Debian 与 RHEL/Rocky/AlmaLinux

安装发行版的 `tshark`/`wireshark-cli` 包，运行 `deploy/linux/install.sh`。通过发行版的 wireshark 组或 `setcap cap_net_raw,cap_net_admin=eip $(command -v dumpcap)` 单独授予 dumpcap 权限；不要以 root 运行 Python Agent。复制两个 systemd unit 到 `/etc/systemd/system`，按实际接口/路径修改后 `systemctl enable --now api-survey-{capture,agent}`。Agent unit 使用 `apisurvey`、`NoNewPrivileges`、`PrivateTmp` 和失败重启。

## 配置与运行

### 整体运行流程与启用 AI 后的变化

**可以自动完成，但不是对正在写入的包逐包实时分析。** 同时启动 capture 与 agent 后，capture
服务先用 dumpcap/tcpdump 按时长或大小轮转文件；agent 每 5 秒扫描一次 `capture/incoming`，只在
文件超过 `stable_seconds` 且连续两次扫描大小不变后，才执行解析、脱敏、聚合、AI 分析和输出。
因此使用 `duration_seconds: 30` 时，通常要等待当前文件轮转，再额外等待稳定检查，而不是发出
一次请求后立即看到文件。单个坏包或临时 AI 错误会被记录为失败并跳过，watcher 会继续处理后续
轮转文件。

无人值守运行需要同时满足：

1. `API Survey Capture` 和 `API Survey Agent` 两个任务都处于运行状态；
2. 抓包接口正确，并且业务流量命中 `capture.filter`；
3. 流量是当前版本支持的明文 HTTP/1.1（HTTPS 只能识别为 TLS，无法直接还原接口）；
4. `ai.enabled: true` 且 `check-ai` 返回 `healthy: true`；
5. 运行任务的账户对 `storage.root`、tshark/dumpcap 和所需证书具有访问权限。

Windows 可用以下命令确认任务和日志：

```powershell
Get-ScheduledTask -TaskName 'API Survey Capture','API Survey Agent' |
  Select-Object TaskName, State
Get-Content .\logs\capture.log -Tail 50
Get-Content .\logs\agent.log -Tail 100
```

成功处理后，主要最终产物位于 `<storage.root>/output/`：每个接口一个
`interfaces/*.json`，汇总索引为 `api-catalog.json`，OpenAPI 为
`openapi/openapi.json`（启用 `generate_openapi` 时），本次摘要为
`reports/analysis-summary.json`。数据库位于 `state/agent.db`，脱敏中间证据位于
`work/redacted/`。`min_samples` 或 `publish_confidence` 未达到时仍会写出当前结果，但接口状态为
`PENDING_MORE_SAMPLES`，后续轮转文件会继续累积样本。

无论是否启用 AI，前半段都是确定性流程：发现稳定 pcap → SHA256 去重与状态恢复 → tshark
协议探测 → HTTP/1.1 字段提取 → 确定性请求/响应配对 → JSON Body 解码 → 静态资源过滤 →
递归脱敏 → Endpoint 归一化和多样本聚合。SQLite 启用时，新样本会与历史脱敏样本合并。

`ai.enabled: false` 时，本地规则根据真实样本推断基础 request/response Schema；`summary` 和
`description` 保持空值，`unknown` 会标记语义说明需要 AI。`ai.enabled: true` 时，每个聚合后
Endpoint 的脱敏样本和字段观测会发送给 AI；AI 可以提供接口摘要、描述、语义化路径参数名、
请求/响应 Schema、字段说明、置信度和不确定项。原始 pcap、原始 Authorization/Cookie 和未
脱敏 Body 不会进入 AI Client。

AI 返回不会直接发布：Pydantic 先验证结构，Evidence Validator 再检查路径覆盖、真实状态码、
请求/响应字段和示例证据。不存在的状态码或字段会成为 validation issue，并降低最终
`confidence`。最终 Standard Interface JSON 保留真实 `observedPaths`、状态码、样本统计与示例，
同时加入 AI 的 `summary`、`description`、`fieldDescriptions`、Schema 和 `unknown`。OpenAPI 从
该事实层二次生成，并用 `x-field-descriptions` 保留 AI 字段说明；AI 不直接生成整份 OpenAPI。

当最终置信度低于 `analysis.publish_confidence`，或样本数少于 `analysis.min_samples`，Endpoint
状态为 `PENDING_MORE_SAMPLES`，但证据和当前接口文档仍会保存以便继续积累。AI 调用失败或
结构化结果解析失败会记录失败并终止本次分析，不会悄悄回退后发布未经验证的 AI 内容。

所有路径通过 `storage.root` 和 `pathlib` 派生。Windows/Linux 示例分别位于 `config/`。API Key 只从 `ai.api_key_env` 指定的环境变量读取；不写入 YAML 或日志。AI 默认关闭，因此无模型也能生成基础事实层。 数据库默认启用，`database.url` 留空时使用 `storage.root/state/agent.db`；如需无数据库运行，可显式设置 `database: {enabled: false, url: ""}`，此模式仍会完整生成接口 JSON、Catalog、OpenAPI 和分析报告。

### AI 配置

当前 AI transport 支持兼容 OpenAI Chat Completions 的 HTTP 服务，并要求模型能够根据
`response_format: {type: json_object}` 返回结构化 JSON。`base_url` 填 API 根地址，代码会
自动追加 `/chat/completions`，所以不要把该后缀重复写入配置：

```yaml
ai:
  enabled: true
  provider: "openai-compatible" # 当前仅用于标识，transport 不根据它切换实现
  model: "你的模型部署名"
  base_url: "https://你的服务地址/v1"
  api_key_env: "AI_API_KEY"
  retries: 2
  trust_env_proxy: false
  proxy_url_env: ""
  tls_verify: true
  ca_bundle: null
  send_response_format: true
```

`model` 必须是服务端接受的模型名或部署名。`retries` 是首次请求失败后的额外重试次数。
需要鉴权时，API Key 只能放在 `api_key_env` 指定的环境变量中，不能把真实密钥写进 YAML。Windows
PowerShell 可使用管理员终端写入机器级变量（计划任务通常以 `SYSTEM` 运行）：

```powershell
[Environment]::SetEnvironmentVariable('AI_API_KEY', '实际密钥', 'Machine')
```

当前 PowerShell 会话如需立即测试，还应同时设置进程级变量：

```powershell
$env:AI_API_KEY = '实际密钥'
```

如果使用无需鉴权的本地或内网自部署模型，将 `api_key_env` 设置为空字符串即可。此时
客户端不会检查环境变量，也不会发送 `Authorization` 请求头：

```yaml
ai:
  enabled: true
  provider: "openai-compatible"
  model: "本地模型名"
  base_url: "http://127.0.0.1:8000/v1"
  api_key_env: ""
  retries: 2
  trust_env_proxy: false
  proxy_url_env: ""
  tls_verify: true
  ca_bundle: null
  send_response_format: false
```

只有确认模型服务所在网络边界可信且服务本身确实不要求鉴权时才应使用此模式。如果填写
了环境变量名称（例如 `AI_API_KEY`），对应变量缺失仍会立即报错，防止意外匿名请求公网服务。
`trust_env_proxy: false` 是默认值，表示 AI 请求不读取 `HTTP_PROXY`、`HTTPS_PROXY` 和
`ALL_PROXY`，适合 localhost 或内网自部署模型，可避免请求被系统代理错误转发。只有访问
外部模型确实必须经过环境代理时才改为 `true`；也可以保持为 `false`，由网络层直接路由。
Postman 的“使用系统代理”不等于 Python 自动获得相同代理，尤其是 Windows 系统代理或 PAC。
推荐将实际代理 URL 放入单独环境变量，并通过 `proxy_url_env` 指定变量名；代理地址或凭据
不写入 YAML，也不会出现在健康检查结果中。例如设置 `proxy_url_env: "AI_HTTPS_PROXY"`。

Windows 上可先查看系统代理来源：

```powershell
netsh winhttp show proxy
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" |
  Select-Object ProxyEnable, ProxyServer, AutoConfigURL
```

获得组织批准的实际代理 URL 后，在当前 PowerShell 中设置并配置显式代理：

```powershell
$env:AI_HTTPS_PROXY = "http://proxy.company.example:8080"
```

```yaml
ai:
  trust_env_proxy: false
  proxy_url_env: "AI_HTTPS_PROXY"
```

如果 `AutoConfigURL` 指向 PAC，httpx 不会执行 PAC 脚本；应从网络管理员取得该目标对应的
实际代理地址，不能把 PAC URL 直接当作代理 URL。计划任务运行时需把变量设置为机器级，
并重启任务：`[Environment]::SetEnvironmentVariable('AI_HTTPS_PROXY', '代理URL', 'Machine')`。

例如 Windows Internet Settings 返回 `ProxyEnable=1`、
`ProxyServer=proxyau.huawei.com:8080` 且 `AutoConfigURL` 为空，而 WinHTTP 显示直连时，说明
Postman 使用的是当前用户 WinINET 代理，不是 WinHTTP 代理。可按下面方式映射给本项目：

```powershell
# 当前 PowerShell 立即生效
$env:AI_HTTPS_PROXY = "http://proxyau.huawei.com:8080"

# 验证代理自身及目标地址（Windows PowerShell 5.1）
Invoke-WebRequest `
  -Uri "https://tpsp.dev.huawei.com/llm/qwen3.6/v1/models" `
  -Proxy "http://proxyau.huawei.com:8080" `
  -ProxyUseDefaultCredentials
```

对应配置使用 `trust_env_proxy: false` 和 `proxy_url_env: "AI_HTTPS_PROXY"`，避免同时继承
其他环境代理。若返回 HTTP 407，说明代理要求 Windows 集成认证；Postman 可以使用当前用户
凭据，但 Python/httpx 默认不会自动执行 NTLM/Kerberos。此时应优先申请服务账号可用的代理、
目标域名直连白名单或运维提供的认证方式，而不是把 Windows 密码写进配置文件。

不要只用 `GET /models` 判断 Chat Completions 是否可用：部分网关没有 models 路由，企业代理
也可能对不同方法或路径采用不同策略。应使用与 Postman **完全相同的 POST URL 和 JSON**
测试。同时检查 `ProxyOverride`；Postman 的“系统代理”会遵循 WinINET 绕过列表，如果其中有
`*.huawei.com`，Postman 实际可能对该域名直连，而不是经过 `proxyau.huawei.com:8080`：

```powershell
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" |
  Select-Object ProxyEnable, ProxyServer, ProxyOverride, AutoConfigURL
```

代理返回带“支持与帮助 / 客服 / 问题反馈”的 HTML 页面，表示请求已到达企业代理，但被其
策略页拦截或上游访问失败，并不能证明模型 API 返回了错误。此时应比较 Postman Console 中
该请求的代理/直连信息、HTTP 方法、完整 URL、Header 和 SSL verification 设置。
`send_response_format` 控制是否发送 OpenAI 的 `response_format: {type: json_object}`。
某些兼容服务（包括只接受你在 Postman 中展示的最小请求体的服务）不支持该参数，可设为
`false`；客户端仍会通过 system prompt 要求 JSON，并继续用 Pydantic 严格验证响应。

### 与既有 Java/OkHttp 客户端对照

既有 Java 实现可以确认网关采用标准的 `POST {baseUrl}/chat/completions`、
`Content-Type: application/json`、非流式 `choices[0].message.content` 响应。本项目现在也显式
发送 Content-Type，并且只在环境变量中确实存在密钥时才发送 `Authorization: Bearer ...`；
不会像某些实现那样在空密钥时发送 `Bearer `。`stream: false`、可选的
`response_format` 和返回 JSON 校验也与该协议边界一致。

Java 片段中的代理、TLS、连接池和 Windows 集成认证实际由
`AbstractLLMClient.getHttpClient()` 决定，而不是 `Request.Builder` 决定。因此 Java 客户端能
访问不能证明请求是直连，也不能证明无代理认证。排查网络差异时最有价值的是继续查看
`getHttpClient()`、`LLMConfig`、JVM 启动参数（`https.proxyHost/https.proxyPort`）和实际 API
Key 来源；流式 SSE、工具调用和 token usage 对当前非流式 Endpoint Schema 分析不是必需项。

补充的 `AbstractLLMClient` 已经给出关键答案：Java 客户端无条件信任所有证书，并关闭
hostname verification；它只在 `LLMConfig.proxyAddress` 非空时使用显式 HTTP 代理，代理仅
支持无认证或 Basic 认证。因此 Java 能调通不能作为 TLS 正常的证据。推荐从运维取得企业
CA PEM 文件并配置 `ca_bundle`，同时保持 `tls_verify: true`：

```yaml
ai:
  tls_verify: true
  ca_bundle: "D:/certs/huawei-enterprise-ca.pem"
```

仅为一次性定位“是否为证书链问题”，可临时设置 `tls_verify: false`；这会同时跳过证书与
主机名校验，等价于 Java 中的 trust-all 行为，存在中间人攻击风险，不应作为生产配置。
客户端会输出 WARNING，`check-ai` 也会返回 `tlsVerified: false`。测试完必须恢复为 `true`。
配置 `ca_bundle` 时，客户端会在 Python 默认可信根证书基础上额外加载企业 CA，而不是关闭
验证或只信任企业 CA。`check-ai` 的请求使用空的合成样本，因此返回 `confidence: 0.0` 也完全
正常；健康判定应看 `healthy` 和 `structuredOutputValid`，不能把该置信度当作真实 Endpoint
的分析质量。结果中的 `syntheticEvidence: true` 会明确标识这一点。

如果关闭 TLS 后错误推进到 `INVALID_STRUCTURED_OUTPUT_ValidationError`，说明网络、代理、TLS
和 HTTP 调用均已成功，剩余问题只是模型内容格式。客户端会把完整
`EndpointAnalysisResult` JSON Schema 放入 system prompt，并兼容单个常见的
```` ```json ... ``` ```` 包装；最终仍必须通过 Pydantic。失败信息只列出字段位置和错误类型，
例如 `normalized_path:missing`，不会把模型返回的业务内容写入日志。此时不应继续修改代理。

还应查看 Java 运行时 `LLMConfig.proxyAddress` 的实际值：为空表示 Java 直连；形如
`host:port` 表示无认证代理；形如 `username:password@host:port` 表示 Basic 代理。请勿提供
真实密码，只需确认属于哪一种情况。

配置完成后，用 `--force` 重新分析已经处理过的 pcap，才能重新调用 AI：

```powershell
.\.venv\Scripts\api-survey.exe --config .\config.yaml analyze "D:\path\traffic.pcapng" --force
```

如果提示 `capture file does not exist`，表示命令中的具体文件名已经不存在（常见于轮转后文件名
变化），不是 AI 故障。先列出当前真实文件，再把 `FullName` 传给 CLI：

```powershell
$captures = Get-ChildItem `
  "D:\CCode\IF\survey-data\capture\incoming" `
  -File |
  Where-Object { $_.Extension -in '.pcap', '.pcapng' } |
  Sort-Object LastWriteTime -Descending

$captures | Select-Object LastWriteTime, Length, FullName
$pcap = $captures | Select-Object -First 1
Test-Path -LiteralPath $pcap.FullName
.\.venv\Scripts\api-survey.exe --config .\config.yaml analyze $pcap.FullName --force
```

在分析真实抓包前，可以使用不包含真实流量的合成请求检查模型连通性、鉴权以及结构化
JSON 输出。成功时命令退出码为 `0`，失败时为 `1`；输出不会包含 API Key：

```powershell
.\.venv\Scripts\api-survey.exe --config .\config.yaml check-ai
$LASTEXITCODE
```

成功结果示例：

```json
{
  "healthy": true,
  "model": "本地模型名",
  "authenticated": false,
  "structuredOutputValid": true,
  "normalizedPath": "/__api_survey_health__",
  "confidence": 1.0
}
```

如果显示 `FAILED_AI_PARSE`，错误后缀会进一步区分：`HTTP_STATUS_404` 通常是
`base_url` 路径不对，`HTTP_STATUS_400` 通常是模型服务不接受请求参数（常见于不支持
`response_format`），`CONNECTION_ERROR_*` 表示地址、端口或网络问题，`TIMEOUT` 表示
60 秒内未响应，`INVALID_CHAT_COMPLETIONS_RESPONSE` 表示响应不是兼容结构，
`INVALID_STRUCTURED_OUTPUT_*` 表示 `message.content` 不是符合结果模型的 JSON。鉴权模式下
提示环境变量未设置时，应重新打开 PowerShell 或重启计划任务。
`CONNECTION_ERROR_ProxyError` 表示旧版本或显式启用代理后，请求被环境代理拦截；本地模型
应设置 `trust_env_proxy: false` 并重新安装当前项目。临时排查也可以在当前 PowerShell 中
设置 `$env:NO_PROXY = "127.0.0.1,localhost,模型服务器IP"`。
`CONNECTION_ERROR_ConnectError` 表示已经绕过代理，但 TCP 连接仍未建立：通常是服务未启动、
IP/端口错误、服务只监听其他网卡、Docker/WSL 未映射端口或防火墙拒绝连接。`check-ai`
输出中的 `endpoint` 是程序实际请求的脱敏地址，可直接据此检查主机、端口和路径。

```powershell
# 将主机和端口替换成 endpoint 中的值
Test-NetConnection -ComputerName 127.0.0.1 -Port 8000
Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
```

如果模型在 Docker 中，还应执行 `docker ps` 并确认端口列包含类似
`0.0.0.0:8000->8000/tcp`；如果在 WSL 中，应先在 WSL 内使用 `curl` 测试，再确认 Windows
能访问该端口。服务只监听 `127.0.0.1` 时只能由同一台主机访问；远程部署应按安全策略监听
可达网卡并配置防火墙，切勿无鉴权暴露到不可信网络。

对于 `https://tpsp.dev.huawei.com/...` 这类远程 HTTPS 地址，应按远程服务排查，不能用
localhost 的端口监听命令代替。先执行：

```powershell
Resolve-DnsName tpsp.dev.huawei.com
Test-NetConnection tpsp.dev.huawei.com -Port 443
Invoke-WebRequest -Method Get -Uri "https://tpsp.dev.huawei.com/llm/qwen3.6/v1/models"
```

如果 DNS 或 443 端口不通，应先连接所需 VPN/办公网络并确认防火墙策略。如果浏览器可访问
但 Python 报 `CONNECTION_ERROR_CERTIFICATE_VERIFY`，通常是企业 TLS 根证书没有进入 Python
使用的 CA 信任链，应向运维获取 CA 文件并正确安装，不建议关闭 TLS 校验。如果必须通过
企业代理访问，应设置 `trust_env_proxy: true`，同时确保 `HTTPS_PROXY` 指向可用代理；出现
`ProxyError` 说明代理本身不可连接或不允许该目标。服务即使“不需要 API Key”，也仍可能
要求 VPN、源 IP 白名单、客户端证书或企业 SSO，这些与 `api_key_env` 是不同的访问控制。

可先绕过本项目，用 PowerShell 直接检查服务的模型列表和 Chat Completions 端点。以下
示例适用于无需鉴权的本地服务；地址应与配置中的 `base_url` 一致：

```powershell
Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:8000/v1/models"

$body = @{
  model = "qwen"
  messages = @(@{ role = "user"; content = "只返回 JSON：{`"ok`":true}" })
  response_format = @{ type = "json_object" }
} | ConvertTo-Json -Depth 10

Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/v1/chat/completions" `
  -ContentType "application/json" `
  -Body $body
```

如果 `/models` 返回的实际模型 ID 不是 `qwen`，应把配置的 `ai.model` 改成返回的精确 ID。

AI 只接收完成递归脱敏后的 Transaction 样本。模型响应还会经过 Pydantic 结构校验和
Evidence Validator；模型无法访问 pcap、文件系统或 Shell。若 AI 服务不可达、密钥缺失、
返回非 JSON 或 JSON 不符合结果模型，本次分析会失败并记录状态，而不会静默发布未经验证
的 AI 内容。若暂时不需要语义说明，保持 `enabled: false` 即可继续生成基础 Schema、接口
JSON、Catalog 和 OpenAPI。

```bash
api-survey --config config.yaml analyze demo.pcapng
api-survey --config config.yaml watch
api-survey --config config.yaml status
api-survey --config config.yaml list-endpoints
api-survey --config config.yaml show-endpoint GET '/users/{value}'
api-survey --config config.yaml generate-openapi
api-survey --config config.yaml list-interfaces
api-survey --config config.yaml doctor
python -m src.agent --config config.yaml --once --input tests/fixtures/demo.pcapng
```

远程抓包只需将 `.pcap`/`.pcapng` 放入 `capture/incoming`。watch 等待 mtime 超过阈值且两次大小一致。默认启用 SQLite，用于跨进程 SHA256 去重、处理状态和中断恢复；`database.url` 留空时数据库位于 `storage.root/state/agent.db`。如显式关闭数据库，分析结果仍直接写入 JSON/YAML 文件，但 `--force` 无需使用。 数据库启用时，脱敏 Transaction 会按 Endpoint 跨多个 pcap 累积，Transaction ID 使用 capture SHA256 命名空间避免不同文件的 frame/stream 冲突；Agent 每次从全部持久化 Endpoint 样本重建 Interface、Catalog 和 OpenAPI。异常中断的分析运行会在下次启动时标记失败并恢复 Capture 状态。`doctor` 会检查工具发现、抓包权限、存储写入和数据库初始化。

### 忽略静态资源

分析阶段默认忽略 `/favicon.ico`、Chrome DevTools 探测路径，以及常见的 CSS、
JavaScript、图片、Source Map 和字体扩展名。规则在 HTTP 事务建立后、写入脱敏样本和
Endpoint 聚合前生效；原始 pcap 不会被修改或删除。
数据库中由旧版本保存的静态 Endpoint 也会在重建输出时被排除，但历史数据库记录仍保留。

```yaml
analysis:
  min_samples: 3
  max_samples_per_endpoint: 20
  publish_confidence: 0.85
  ignore_paths:
    - "/favicon.ico"
    - "/.well-known/appspecific/com.chrome.devtools.json"
    - "/static/*" # 支持 glob；按需添加
  ignore_extensions: [".css", ".js", ".map", ".png", ".jpg", ".svg", ".ico", ".woff2"]
```

匹配不区分大小写。`ignore_extensions` 只按 URL 路径的最后扩展名匹配，默认不忽略
`.json`，避免误删真实 JSON API。如果业务接口本身以 `.js` 等后缀结尾，请从列表中
删除对应扩展名。设为 `ignore_paths: []` 和 `ignore_extensions: []` 可完全关闭过滤。

## 数据、输出与安全

目录自动创建为 `capture/incoming`、`work/{raw,transactions,redacted}` 与 `output/{interfaces,openapi,reports,samples}`。SQLite 默认启用并创建 `state/agent.db`；只有显式设置 `database.enabled: false` 时才不使用数据库。 所有 Interface、Catalog、OpenAPI 和报告先写同目录临时文件并通过原子替换发布，避免服务崩溃或并发读取时得到半写文件。核心产物 `output/interfaces/*.json` 包含 host/method/path、请求与响应 schema/example、样本统计、真实 observed path/status、置信度和未知项。`api-catalog.json` 建立资产索引；`openapi/openapi.{json,yaml}` **只由标准接口 JSON** 二次生成；`reports/analysis-summary.json` 记录摘要。 标准接口 JSON 的 `request.bodyObserved` 明确记录是否真实观测到请求体；OpenAPI 生成器依据该证据决定是否输出 `requestBody`，因此空对象、空数组、`0`、`false` 和空字符串不会被误删。旧接口 JSON 没有此标记时，仅将非 `null` 的 `request.example` 视为请求体证据；旧数据中的 JSON `null` 无法与未观测请求体可靠区分。

Authorization、Cookie、API key、密码、token、手机号等配置化字段在嵌套对象/数组中递归替换为 `***`。外部 AI client 只接受内存中的脱敏 Transaction，不接收 pcap/raw 路径且没有 shell 能力。原始 pcap 永不自动删除。Validator 拒绝未观测状态、字段、路径和示例；低置信度或样本不足会进入 `PENDING_MORE_SAMPLES`。

## 故障排查

* “tshark/dumpcap not found”：安装 Wireshark CLI，并检查 PATH 或配置绝对路径。
* Wireshark 安装时没有 Npcap 页面：先运行 `Get-Service npcap` 和 `dumpcap -D`；能列出接口就无需重复安装，否则从 Npcap 官方安装程序单独安装。Microsoft Store/便携版或企业重打包版本可能不附带 Npcap。
* Npcap 安装提示 `Failed to completely uninstall Npcap; files in use by: svchost.exe`：通常表示机器上已有 Npcap，安装程序正在升级或重装，但旧驱动正被 Windows 网络服务占用。不要在任务管理器中强制结束 `svchost.exe`。先取消安装并运行 `Get-Service npcap`、`dumpcap -D`；若能列出接口即可继续使用现有版本。确需升级时，先停止 API Survey/Wireshark 等抓包程序并重启 Windows，登录后立即以管理员身份运行 Npcap 安装器；仍失败则从“已安装的应用”卸载 Npcap、重启，再安装新版。
* `dumpcap: Unable to load Npcap (wpcap.dll)`：表示 Wireshark/dumpcap 已安装，但 Npcap 用户态 DLL 或驱动缺失、损坏、版本不匹配，或者前一次升级没有完成；“已安装的应用”里出现 Npcap 不代表它当前可用。先重启 Windows 再测试。仍失败时，从“已安装的应用”卸载 Npcap（以及遗留 WinPcap），重启，以管理员身份安装与系统架构匹配的最新版 Npcap，再次重启。最后确认 `Get-Service npcap` 有结果、`Test-Path "$env:SystemRoot\System32\Npcap\wpcap.dll"` 返回 `True`，且 `dumpcap -D` 能列出接口。不要从第三方网站单独下载 `wpcap.dll`，也不要把 DLL 手工复制到 Wireshark 目录。
* `UnicodeDecodeError: 'gbk' codec can't decode ...` 或随后出现 `result.stdout is None`：这是旧版本在中文 Windows 上用系统 ANSI/GBK 解码 dumpcap 输出导致的，不是网卡或 Npcap 故障。更新项目并重新执行 `pip install --force-reinstall --no-deps .`；新版以二进制读取并使用容错 UTF-8 解码。临时绕过可在执行前设置 `$env:PYTHONUTF8='1'`，但仍建议升级代码。
* dumpcap permission denied：配置 wireshark 组/capabilities；Agent 不应以 root 运行。
* `BLOCKED_TLS`：V1 不猜测 TLS 明文，请提供明文 HTTP 测试流量。
* `FAILED`：运行 `status` 并查看一致格式的服务日志；数据库保留 error 与状态。
* AI 失败：确认 provider 兼容 chat-completions JSON 输出、模型名、base URL 和环境变量。

## 测试与跨平台一致性

```bash
pytest
```

同一最小脱敏 fixture 分别在 Windows/Linux 运行 `api-survey analyze`；比较 `api-catalog.json`（忽略 `generatedAt`）和 `interfaces/*.json`。核心分析不读取 OS 信息，平台差异仅位于 adapter、capture backend、部署脚本及配置。
