# R0 对战平台 / R0Guard 反作弊 安全分析报告

| 项目 | 内容 |
|------|------|
| 报告标题 | R0 对战平台客户端及 R0Guard 反作弊组件安全分析 |
| 目标产品 | R0 对战平台(`r0_arena`)v2.0.95 + R0Guard 反作弊套件 |
| 发布者 | 湖南（衡阳）某科技有限公司（统一社会信用代码 91341200MA8PP8HF34，GlobalSign EV 代码签名） |
| 分析日期 | 2026-06-14 |
| 分析方法 | 纯静态分析 + 隔离虚拟机内存取证（asar 解包、PE 结构/熵分析、Ghidra 反汇编、frpc/R0Guard 进程内存 dump 字符串还原、Procmon 行为日志） |
| 执行环境 | 全程未在分析者宿主机运行样本；动态 dump 由用户在隔离虚拟机内完成 |
| 总体结论 | **高危。** 反作弊组件在本机运行一个具备「任意文件读写 / 命令执行 / 实时屏幕直播 / 进程操控 / 网络侦察」能力的 HTTP 控制服务器，并通过随客户端自启的 frp（内网穿透）反向隧道将其暴露到发行商公网服务器。其能力面与远程访问木马（RAT）在技术上不可区分。 |

---

## 1. 执行摘要（Executive Summary）

R0 对战平台由两部分组成：

1. **Electron 桌面客户端 `r0_arena`**——加载远程页面 `https://desktop-app.r0csgo.com`，存在多项 Electron 安全反模式（关闭证书校验、远程页面开启 Node 集成、本机无鉴权 API 暴露 token 与 SSRF 接口）。
2. **`R0Guard` 反作弊套件**——三个核心模块（exe + 32/64 位 DLL）均使用 **VMProtect** 虚拟化加壳；其主程序在 `127.0.0.1:54425` 运行一个 HTTP「dashboard」控制服务器；随附经发行商 EV 证书签名的 **frpc**（fatedier/frp 内网穿透客户端），开机即把上述 54425 端口反向隧道暴露到发行商服务器 `local-api-direct.r0csgo.com:20046` 下的按机器专属子域名。

**核心风险**：54425 控制服务器提供的接口（任意文件下载/上传/读写、`/api/execute_command` 命令执行、H.264 屏幕实时直播、进程枚举/结束、注册表/磁盘探测、网络扫描、HWID/TPM/Steam 身份获取）远超反作弊所需，且被设计为可经互联网由发行商远程调用。一旦发行商服务器被入侵或内部权限被滥用，等同于所有装机用户的主机被批量远程控制。

---

## 2. 风险评级汇总

| ID | 发现 | 组件 | 严重度 |
|----|------|------|--------|
| F-01 | 反作弊本机控制服务器具备 RAT 级能力（文件/命令/屏幕/进程） | R0Guard `:54425` | 🔴 严重 |
| F-02 | frpc 反向隧道将本机控制服务器暴露到发行商公网 | R0Guard + frpc | 🔴 严重 |
| F-03 | `/api/execute_command` 远程任意命令执行 | R0Guard `:54425` | 🔴 严重 |
| F-04 | 关闭 TLS 证书校验（`ignore-certificate-errors`）+ 远程页面开启 Node 集成 → 可被 MITM 导致 RCE | Electron 客户端 | 🔴 严重 |
| F-05 | 本机 AC API（54427）无鉴权 + CORS `*`，暴露用户 token | Electron 客户端 | 🟠 高 |
| F-06 | `/get_large_file?url=` SSRF 代理（无主机白名单） | Electron 客户端 | 🟠 高 |
| F-07 | `window.open` 处理器对任意 URL 一律放行并开启 Node 集成 | Electron 客户端 | 🟠 高 |
| F-08 | 静态文件服务绑定 0.0.0.0（局域网可达）+ 路径穿越 | Electron 客户端 | 🟡 中 |
| F-09 | 全部反作弊核心模块 VMProtect 加壳，规避静态审计 | R0Guard | 🟡 中（透明度） |
| F-10 | 捆绑高权限 VAC 屏蔽/注册表/提权辅助工具 | 安装包 | 🟡 中 |

---

## 3. 关键攻击链（已完整验证）

```
 [互联网] 发行商后台 / 任何可达专属子域名者
     │  HTTP 访问  https://2b2e975a4a790791.local-api.r0csgo.com
     ▼
 [发行商 frps]  local-api-direct.r0csgo.com:20046
     │  （frp token: nEF3B3bmJgmntR0CeIEJWyHAr3lwGA62）
     │  frp 反向隧道  type=http  subdomain=2b2e975a4a790791
     ▼
 [用户主机]  frpc.exe  ──►  127.0.0.1:54425
                              ▲
                              └── R0Guard.exe 本机 HTTP 控制服务器
                                  （任意文件/命令/屏幕/进程/网络）
```

**Procmon 证据**——frpc 随客户端自启，配置运行时生成于临时目录（随机名，因此磁盘上不留痕）：
```
"C:\r0_guard\resources\frpc.exe" -c "C:\Users\...\AppData\Local\Temp\frpc_cbf592fdf46d4492af248e5d1ad9c327.toml"
```

**frpc 内存 dump 还原出的实际配置**：
```toml
serverAddr = "local-api-direct.r0csgo.com"
serverPort = 20046
auth.method = "token"
auth.token  = "nEF3B3bmJgmntR0CeIEJWyHAr3lwGA62"
transport.heartbeatInterval = 10
transport.heartbeatTimeout  = 30

[[proxies]]
name      = "http-2b2e975a4a790791"
type      = "http"
localIP   = "127.0.0.1"
localPort = 54425
subdomain = "2b2e975a4a790791"
```

---

## 4. 详细发现

### F-01 / F-03：反作弊本机控制服务器（RAT 级能力）— 严重

**监听进程确认**：`127.0.0.1:54425` 由 **`R0Guard.exe`（反作弊主进程）** 自身监听。判定依据——该端口的 HTTP 服务器完整生命周期日志、路由表与处理函数代码均位于对 `R0Guard.exe` 进程所做的内存 dump 中：

```
[..:34:07.566] [INFO] HTTP server starting on port 54425
[HttpServer] Port shared memory initialized with port 54425
HTTP server started successfully on port 54425
```

即 HTTP 控制服务器运行在 `R0Guard.exe` 进程内。R0Guard 选定端口后，会将端口号写入**文件**（"Port saved to file: 54425"）与**共享内存**（`[HttpServer] Port shared memory initialized with port`）以供其它模块（注入的 `R0GuardDll64.dll`、`steam_worker.exe`、Electron 客户端）发现；frpc 配置中的 `localPort = 54425` 即与该端口一致，证明 frpc 转发的正是 R0Guard 主进程监听的控制端口。

> 端口选择逻辑：默认 54425，被占用时自动顺延（"HTTP port: 54425 (will auto-select if…)"）。frpc 配置在运行时按 R0Guard 实际选定的端口生成。

R0Guard.exe 在 `127.0.0.1:54425` 运行 HTTP 服务器。从进程内存还原出的路由表包含以下高危端点（节选）：

**文件操作（远程读写/外传你的硬盘）**
`/api/dashboard/files/read`、`/files/download`、`/files/upload`、`/files/save`、`/files/delete`、`/files/rename`、`/files/mkdir`、`/api/download_file`、`/api/browse_file`、`/api/list_directory`、`/api/open_directory`、`/api/extract_archive`

**命令执行**
`/api/execute_command`——内存中该字符串紧邻 `cmd.exe`、`/c`、`CreateProcessW`，确认为远程任意命令执行。

**屏幕监控（已实现）**
`/api/dashboard/screenshot/{dwm,dxgi,nvidia,amd,mag}`、`/api/dashboard/stream/flv`（H.264 实时屏幕直播，代码完整：FLV Stream client connected / fps / bitrate / GOP）、`/api/dashboard/screens`、`/api/overlay/show`

**进程 / 系统控制**
`/api/dashboard/processes`、`/processes/kill`、`/api/dashboard/registry/test`、`/disks/test`、`/api/dashboard/dll-injections`

**网络侦察（以受害主机为跳板）**
`/api/network/{ping,quickping,tcping,traceroute,dns,speedtest,findping}`——其中 speedtest 接受 `cookie / referer / user_agent / max_redirects / ignore_certificate_errors` 等参数，构成可远程驱动的 HTTP 客户端（SSRF）。

**身份 / 外传**
`/get_machine_token`、`/get_tpm_machine_id`、`/get_steamid`、`/api/steam/switch`、`/api/anticheat/file/upload`、`/dump/upload`、`/screenshot/upload`

> **鉴权边界（客观说明）**：54425 存在鉴权层（`/dashboard/login`、`/dashboard/auth`、`dashboard_session` cookie、"未授权访问 / Missing token"）。因此并非互联网任何人可随意进入，门槛为「专属子域名 + dashboard 凭据 + frp token」。但这些密钥均由发行商掌握——该设计的意图即"发行商可远程访问/控制客户端"，锁是为发行商访问模型服务，而非保护用户。
>
> **更正**：`/api/dashboard/rdp/*`（远程桌面）当前为桩函数（内存提示"远程桌面功能暂未实现"），尚未实装；但屏幕实时直播（FLV）已实装，监控效果等价。

### F-02：frpc 反向隧道暴露本机控制服务器 — 严重

详见第 3 节攻击链。要点：
- frpc 为正版 `github.com/fatedier/frp` 客户端（Go 1.25.4 编译），由发行商用与 R0Guard、Electron 客户端**同一张 EV 证书**重新签名。
- 隧道为 `type=http` + 专属 `subdomain`，将本机回环 54425 暴露到公网，绕过其"仅 127.0.0.1 监听"的本地约束。
- 配置运行时生成于 `%TEMP%`、随机文件名，规避磁盘取证。

#### F-02.1：frpc 配置来源 —— 由 R0Guard 本地用硬编码常量拼装（非服务器下发）

对 `R0Guard.exe` 内存分析表明，frpc 配置**不是从服务器下载的**，而是 R0Guard 进程内用**硬编码常量 + 运行时值**拼装后写入临时文件。R0Guard 常量池中并列存放着以下静态字面量：

```
local-api-direct.r0csgo.com                        ← serverAddr（硬编码）
nEF3B3bmJgmntR0CeIEJWyHAr3lwGA62                    ← auth.token（硬编码）
local-api.r0csgo.com                               ← vhost 基域
\resources\frpc.exe                                ← frpc 路径
%08lx%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x       ← GUID 格式（生成临时文件名）
.toml   frpc_   \logs\frpc.log
```

随后紧跟内嵌的 TOML 模板（sprintf 拼接）：
```toml
serverAddr = "<硬编码>"
serverPort = <硬编码整数 20046>
auth.method = "token"
auth.token = "<硬编码>"
transport.heartbeatInterval = 10
transport.heartbeatTimeout = 30
transport.tcpMux = true
transport.poolCount = 1
[[proxies]]
name = "http-<机器ID>"
type = "http"
localIP = "127.0.0.1"
localPort = <运行时选定端口 54425>
subdomain = "<机器ID>"
```

**生成流程**：
1. R0Guard 启动 HTTP 控制服务器，选定本地端口（默认 54425），写入文件 + 共享内存；
2. 从硬编码常量取 `serverAddr / serverPort / token`；`localPort` 填选定端口；`subdomain` / `name` 填**本机派生的机器 ID**（如 `2b2e975a4a790791`）；
3. 拼成完整 TOML 写入 `%TEMP%\frpc_<随机GUID>.toml`（日志："FRP config created: …frpc_cbf592fdf46d4492af248e5d1ad9c327.toml"；随机 GUID 由上述格式现场生成，故每次启动文件名不同、磁盘不留固定痕迹）；
4. 启动 `…\resources\frpc.exe -c <该toml>`，日志写入 `\logs\frpc.log`。

**关键判定**：
- `serverAddr / serverPort / token` 均**硬编码在 `R0Guard.exe` 内**（各仅出现一次，与 frpc 路径、模板同处常量段）→ **该 frp token 是所有安装共用的同一静态密钥**，可被轻易提取（本次已提取），比"按机下发"风险更高。
- `subdomain` 为**本机派生的机器指纹**（仅出现在 FRP/proxy 上下文，任何服务器响应中均无）→ 本地生成、每机一个稳定子域。
- 与服务器的交互（`/v2/auth/upload_client_port`、`/v2/auth/upload_m_info_v2`）是 R0Guard 将端口 / 机器信息**上报**后台（含日志 "Upload client port failed: %S"），**而非获取隧道配置**。
- **后果**：掌握该硬编码 token + 目标机器子域（机器指纹）者，即可经同一 frps（`local-api-direct.r0csgo.com:20046`）触达任意客户端的控制服务器。

涉及的发行商接口：`https://api.r0csgo.com/v2/auth/{check_pass, upload_client_port, upload_m_info_v2, upload_steaminfo_v2}`、`https://ac-api.r0csgo.com`、`https://ac-api-v3.r0csgo.com`。

### F-04：关闭证书校验 + 远程页面 Node 集成 — 严重（Electron 客户端）

- `dist-electron/main.js:85`：`app.commandLine.appendSwitch('ignore-certificate-errors')` 全局禁用 TLS 证书校验。
- `dist-electron/windows/mainWindow.js:124-143`：主窗 `nodeIntegration:true` + `contextIsolation:false`，却 `loadURL('https://desktop-app.r0csgo.com')` 加载远程页面。
- **组合影响**：同网络攻击者可 MITM 劫持远程页面、注入 JS，该 JS 直接拥有完整 Node/操作系统权限 → 远程代码执行。

### F-05：本机 AC API 无鉴权 + CORS `*` 暴露 token — 高（Electron 客户端）

- `dist-electron/services/acHttpServer.js`：监听 `127.0.0.1:54427`，所有响应 `Access-Control-Allow-Origin: *` 且无鉴权。
- `/get_user_token`、`/get_user_info`、`/get_user_uid` 返回登录用户 token 与信息 → 用户浏览的任意网站均可 `fetch` 窃取会话 token（盗号）。

### F-06：`/get_large_file?url=` SSRF — 高（Electron 客户端）

- `acHttpServer.js:258-316` → `largeFileFetcher.js`：服务端抓取任意 `url` 并回传响应体，跟随最多 5 次重定向，无主机白名单。仅支持 http/https（不可读本地文件），属 SSRF 而非 LFI。可探测内网、云元数据等。

### F-07：`window.open` 处理器无条件放行 + Node 集成 — 高（Electron 客户端）

- `dist-electron/ipc/browserWindow.js:54-58`：`setWindowOpenHandler` 对任意 `window.open()` 返回 `action:'allow'`，新窗 `nodeIntegration:true`。`create-browser-window` / `load-url-for-window` 等 IPC 允许渲染层用任意 webPreferences 加载任意 URL。

### F-08：静态文件服务局域网暴露 + 路径穿越 — 中（Electron 客户端）

- `dist-electron/services/httpServer.js:122`：`server.listen(port)` 未指定 host，绑定 0.0.0.0（局域网可达）。
- 第 86-87 行 `path.join(publicDir, decodeURI(pathname))` 未过滤 `..`，存在路径穿越读取风险。

### F-09：VMProtect 加壳规避审计 — 中（透明度）

- R0Guard.exe / R0GuardDll32.dll / R0GuardDll64.dll 均为 VMProtect 3.x（随机垃圾节名如 `.A&8 .T{` .` "4` / `.1>1 .Mzs .4Go`，原节区 RawSize=0，巨型高熵打包节熵 7.81–7.97，入口为 `PUSH/CALL VM + INT1` 反调试桩，DLL 导入表混淆为每库仅 1 个种子导入）。
- "加密强度"说明：VMProtect 的机密性来自代码虚拟化 + 多态 handler + 轻量自解密流（密钥内嵌），**无可度量的密码学位强度**；真正壁垒是逆向成本而非抗密码分析。其效果是阻碍第三方安全审计——对一款拥有上述高权限能力的软件而言，这种不透明本身构成风险。

### F-10：捆绑高权限系统工具 — 中（安装包）

- `plugin/...VAC屏蔽修复工具...bat`：管理员权限运行，执行 `bcdedit /debug off`、`/deletevalue nx/nointegritychecks`、改防火墙/服务、`taskkill Steam`。
- `resources/vbs/*`：注册表读写助手；`isAdmin.exe` / `elevate.exe` / `PrintScr.exe`（提权 / 截图）。属功能性组件，但整体提升了系统权限面。

---

## 5. 失陷指标（IOCs）

| 类型 | 值 |
|------|----|
| frps 控制服务器 | `local-api-direct.r0csgo.com:20046` |
| frp 虚拟主机基域 | `*.local-api.r0csgo.com` |
| 本机专属子域 | `2b2e975a4a790791.local-api.r0csgo.com` |
| frp 鉴权 token | `nEF3B3bmJgmntR0CeIEJWyHAr3lwGA62` |
| 本地被暴露服务 | `127.0.0.1:54425`（**由 `R0Guard.exe` 进程监听**的 HTTP 控制器；端口经文件 + 共享内存发布，默认 54425、占用则顺延） |
| 本地 AC API | `127.0.0.1:54427`（Electron，暴露 token / SSRF） |
| 本地静态服务 | `0.0.0.0:54428` |
| frpc 配置路径 | `%TEMP%\frpc_<32hex>.toml`（运行时生成） |
| 客户端远程域 | `https://desktop-app.r0csgo.com` |

### 文件哈希（SHA-256）

| 文件 | SHA-256 |
|------|---------|
| R0Guard.exe | `03B73804CDD6EE4EA363C233216E9BC36EAE98772548D8CBD8AC10A9A60B3D24` |
| R0GuardDll32.dll | `3506F959822D0D7E336FCAFDF5E82091B288FC7095755781F6FC95DF66CEE859` |
| R0GuardDll64.dll | `10D909C9C7777C424BF93A71E31B92D457920E7BC7E28FCA458327C7EFBEDA71` |
| steam_worker.exe | `A6A463C3D99CFAD7A4E671A10651975098F852B4E0F315249FDA9FE45DEB90E7` |
| R0Installer.exe | `3A803379B89741A0ABE3465000932581163EF90774E6B4984F1DC1A13B01242E` |
| frpc.exe | `9C9FD1AB06198B6D0AA3222006A7F97E2CB29C5EA3AB1D5F408784C008A32515` |

---

## 6. 影响评估

- **机密性**：高——远程可读取/下载任意本地文件、获取屏幕画面、HWID/TPM/Steam 身份、Electron 会话 token。
- **完整性**：高——远程可写入/删除文件、执行任意命令、结束进程、切换 Steam 账号。
- **可用性**：中——可远程结束进程 / 触发封禁。
- **横向移动**：中高——网络扫描 + SSRF 可将受害主机用作内网跳板。
- **规模化风险**：发行商 frps 单点掌控所有客户端隧道；一旦其服务器或证书被攻陷，影响波及全部装机用户。

---

## 7. 处置建议

### 给用户
1. 若非必要，**在隔离/专用游戏环境（独立账户或虚拟机）外不要运行**该客户端；它对主机拥有远程文件/命令/屏幕级能力。
2. 已安装的，建议彻底卸载并检查 `%TEMP%` 残留 `frpc_*.toml`、确认开机自启项与残留服务。
3. 出网层面可阻断 `*.r0csgo.com:20046` 与 frp 隧道域名以切断远控通道（但会影响平台功能）。

### 给发行商（如进行负责任披露）
1. **移除 frp 反向隧道**或改为最小权限、按需授权、用户可见可控的会话；严禁默认开机自启暴露控制服务器。
2. **下线/重构 dashboard 控制面**：`execute_command`、`files/*`、`stream`、`processes/kill`、`extract_archive` 等不应存在于面向用户机器的可远程调用接口；如需取证，应改为用户知情同意、范围受限、审计留痕的明确流程。
3. Electron 客户端：删除 `ignore-certificate-errors`；主窗启用 `contextIsolation` + 关闭 `nodeIntegration` + preload 白名单；AC API 去除 CORS `*` 并加鉴权；`get_large_file` 加目标白名单；静态服务绑定 127.0.0.1 并规范化路径；`window.open` 加 URL 白名单。
4. 公开说明反作弊的数据采集与远程访问范围，提供隐私政策与用户同意机制。

---

## 8. 附录：方法与产物

- **解包**：`@electron/asar` 提取 `app.asar` 中 `dist-electron/` 全部 29 个源文件（TS 编译产物，未混淆）。
- **PE/熵分析**：`pefile` + 自定义香农熵 / χ² 随机性检验，识别 VMProtect。
- **反汇编**：Ghidra（入口桩 `PUSH R8; CALL …; INT1`）。
- **内存取证**：用户在隔离虚拟机内对 `frpc.exe` / `R0Guard.exe` 做完整进程 dump + Procmon 行为日志；分析者对 dump 做字符串还原（含 UTF-16），从中恢复 frpc 实配置与 R0Guard 路由表。
- **取证产物**：`frpc.exe_*.dmp`、`R0Guard.exe_*.dmp`、`Logfile.PML`。

> 声明：本报告基于静态分析与内存取证；VMProtect 使部分实现细节无法完全静态确认。RAT 级能力的判定依据为还原出的接口路由表与处理函数字符串，其"可被远程调用"由 frpc 实配置佐证。建议如需司法/合规用途，补充对各端点鉴权强度与实际服务端调用记录的进一步验证。

*—— 报告结束 ——*
