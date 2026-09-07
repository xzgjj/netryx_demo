# 调研:netryx(MIT,纯 Python 零依赖局域网扫描方案)

调研日期 2026-09-07,在本机真实网络(192.168.3.0/24)实测。

## 项目概况

- 仓库:https://github.com/UbhiTS/netryx (MIT,活跃更新)
- 结构:单文件引擎 `netryx.py`(约 166 KB)+ 单文件 UI `ui.html`(约 121 KB)+ 可选 `netryx_mcp.py`
- 依赖:**仅 Python 标准库**(http.server/socket/concurrent.futures…),零第三方依赖
- 运行:`python netryx.py` 起本地服务并打开浏览器;`--scan <CIDR> --json` 一次性 CLI 扫描;
  `--host 0.0.0.0` 供局域网内手机访问;`--port` 自定义端口
- 预编译产物:Releases 页提供 Windows .exe / AppImage / deb
- 许可:MIT(可商用可修改)

## 能力清单(README 与源码核对)

- 发现:子网自动探测、并发 ping+TCP fallback(挡 ping 的设备也能找到)、ARP 解析 MAC
- 识别:OUI 厂商库(内置,可一键下载全量 IEEE OUI)、mDNS/Bonjour、SNMP v2c、NetBIOS、
  SSDP/UPnP(设备型号)、TTL 系统猜测、设备类型猜测、反向 DNS、往返延迟
- 端口:并发 TCP connect,Quick(~90)/Extended(1-1024)/Full(1-65535),服务名+banner 抓取,
  HTTP/HTTPS 端口识别为可点击 URL(80/443/8080/8443/8123…),TLS 证书信息,暴露风险分级
  (none→critical,基于 Telnet/RDP/SMB/VNC/裸数据库等)
- 视图:表格(默认)/卡片/交互拓扑图(多布局、物理模拟),搜索/过滤/排序,实时监控
  (定时重扫+新设备检测+浏览器桌面通知),扫描历史+变更对比,基线+rogue 告警
- 动作:Wake-on-LAN、设备自定义名/备注、CSV/JSON 导出
- 自动化:one-shot CLI(--json)、OpenAPI(/openapi.json)、HTTP+stdio MCP 服务器、
  SSE/长轮询/Webhook/MQTT 事件推送、API token 管理
- 认证:内置登录(PBKDF2 哈希),默认 admin/admin;NETRYX_OPEN=1 可免登录(不建议)
- 数据:JSON 持久化于数据目录(netryx-data/,扫描历史/命名/厂商库/基线/事件/token;源码 imports 无 sqlite3,纯 JSON)

## 本机实测记录

| 项 | 命令 | 结果 |
|---|---|---|
| 服务启动 | `python netryx.py --no-browser --port 8765` | 登录页 200 |
| 网段扫描 | `python netryx.py --scan 192.168.3.0/24 --json --no-mdns --no-snmp` | 3 台设备:192.168.3.1 华为路由(网关+DNS,UPnP WS5800-10)、192.168.3.209(随机 MAC 手机隐私地址)、192.168.3.235 本机 |
| 单机端口 | `python netryx.py --scan 192.168.3.1 --ports --profile quick --json` | 25/53/80/110/143/443;80→`http://192.168.3.1` 可点击;443 TLSv1.3 证书 CN=`mediarouter.home` |
| 手机端 | playwright 390×844 视口 | 登录页/仪表盘/扫描中布局可用;发现 Scan 按钮溢出 → 已加移动端适配(@media) |

## 评估结论

- 功能覆盖:设备发现+识别 / 端口服务 / 连接拓扑 / 手机网页 / 管理动作 —— **全部命中**
- 约束符合:零依赖、免 Docker、本机 Windows 直接跑、MIT
- 风险:1★ 新项目(2026-08 起活跃),无大规模用户验证;华为消费级路由无开放管理 API,故
  "踢设备"类动作不可做(只读+改名备注+WoL 可做)
- 采纳决策:作为 Demo 基底复用,前端做移动端微调;不自行重写引擎
