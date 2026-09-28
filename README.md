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
```

只有确认模型服务所在网络边界可信且服务本身确实不要求鉴权时才应使用此模式。如果填写
了环境变量名称（例如 `AI_API_KEY`），对应变量缺失仍会立即报错，防止意外匿名请求公网服务。

配置完成后，用 `--force` 重新分析已经处理过的 pcap，才能重新调用 AI：

```powershell
.\.venv\Scripts\api-survey.exe --config .\config.yaml analyze "D:\path\traffic.pcapng" --force
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

如果显示 `FAILED_AI_PARSE`，通常表示服务不可达、接口并非兼容的
`/chat/completions`、模型不支持 `response_format: json_object`，或返回内容不符合结构化
结果模型。鉴权模式下提示环境变量未设置时，应重新打开 PowerShell 或重启计划任务。

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
