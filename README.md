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

从 Wireshark 官方安装器安装 Wireshark CLI、dumpcap 与 Npcap，工具会从 `PATH` 或 `C:/Program Files/Wireshark` 查找。运行 `deploy/windows/install.ps1`，编辑 Windows 示例配置，然后以管理员身份运行 `install_task.ps1`。它创建开机启动且失败重试的 **API Survey Capture** 与 **API Survey Agent** 任务，日志写入 `logs/`。

### Ubuntu/Debian 与 RHEL/Rocky/AlmaLinux

安装发行版的 `tshark`/`wireshark-cli` 包，运行 `deploy/linux/install.sh`。通过发行版的 wireshark 组或 `setcap cap_net_raw,cap_net_admin=eip $(command -v dumpcap)` 单独授予 dumpcap 权限；不要以 root 运行 Python Agent。复制两个 systemd unit 到 `/etc/systemd/system`，按实际接口/路径修改后 `systemctl enable --now api-survey-{capture,agent}`。Agent unit 使用 `apisurvey`、`NoNewPrivileges`、`PrivateTmp` 和失败重启。

## 配置与运行

所有路径通过 `storage.root` 和 `pathlib` 派生。Windows/Linux 示例分别位于 `config/`。API Key 只从 `ai.api_key_env` 指定的环境变量读取；不写入 YAML 或日志。AI 默认关闭，因此无模型也能生成基础事实层。

```bash
api-survey --config config.yaml analyze demo.pcapng
api-survey --config config.yaml watch
api-survey --config config.yaml status
api-survey --config config.yaml list-endpoints
api-survey --config config.yaml show-endpoint GET '/users/{value}'
api-survey --config config.yaml generate-openapi
api-survey --config config.yaml list-interfaces
python -m src.agent --config config.yaml --once --input tests/fixtures/demo.pcapng
```

远程抓包只需将 `.pcap`/`.pcapng` 放入 `capture/incoming`。watch 等待 mtime 超过阈值且两次大小一致。SQLite SHA256 唯一键避免重复，`analyze --force` 可重跑；中断状态可恢复。

## 数据、输出与安全

目录自动创建为 `capture/incoming`、`work/{raw,transactions,redacted}`、`state/agent.db` 与 `output/{interfaces,openapi,reports,samples}`。核心产物 `output/interfaces/*.json` 包含 host/method/path、请求与响应 schema/example、样本统计、真实 observed path/status、置信度和未知项。`api-catalog.json` 建立资产索引；`openapi/openapi.{json,yaml}` **只由标准接口 JSON** 二次生成；`reports/analysis-summary.json` 记录摘要。

Authorization、Cookie、API key、密码、token、手机号等配置化字段在嵌套对象/数组中递归替换为 `***`。外部 AI client 只接受内存中的脱敏 Transaction，不接收 pcap/raw 路径且没有 shell 能力。原始 pcap 永不自动删除。Validator 拒绝未观测状态、字段、路径和示例；低置信度或样本不足会进入 `PENDING_MORE_SAMPLES`。

## 故障排查

* “tshark/dumpcap not found”：安装 Wireshark CLI，并检查 PATH 或配置绝对路径。
* dumpcap permission denied：配置 wireshark 组/capabilities；Agent 不应以 root 运行。
* `BLOCKED_TLS`：V1 不猜测 TLS 明文，请提供明文 HTTP 测试流量。
* `FAILED`：运行 `status` 并查看一致格式的服务日志；数据库保留 error 与状态。
* AI 失败：确认 provider 兼容 chat-completions JSON 输出、模型名、base URL 和环境变量。

## 测试与跨平台一致性

```bash
pytest
```

同一最小脱敏 fixture 分别在 Windows/Linux 运行 `api-survey analyze`；比较 `api-catalog.json`（忽略 `generatedAt`）和 `interfaces/*.json`。核心分析不读取 OS 信息，平台差异仅位于 adapter、capture backend、部署脚本及配置。
