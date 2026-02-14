# 网络过滤 (Network Filter)

## 概述

AppContainer 原生的网络控制是粗粒度的——通过 `internetClient`、`internetClientServer`、`privateNetworkClientServer` 三个 capability 控制，要么全开要么全关。

**Network Filter** 提供细粒度的网络控制能力，支持按 IP 地址/CIDR 段、端口、协议（TCP/UDP）和域名进行过滤，同时支持白名单和黑名单模式。**不需要管理员权限。**

## 原理

```
Launcher (AppContainer.exe)
  │
  ├─ 读取 config.ini [NetworkFilter] 或 CLI -n 参数
  ├─ 将规则写入环境变量 _NETFILTER_DEFAULT / _NETFILTER_CONNECT / _NETFILTER_DNS
  ├─ 调用 DetourCreateProcessWithDllExW（替代 CreateProcessW）
  │    └─ 在子进程创建时注入 NetFilter.dll
  │
  └─ 子进程 (AppContainer 沙箱)
       └─ NetFilter.dll 作为首个导入项加载
             ├─ DllMain: 读取环境变量中的规则，解析
             ├─ 通过 Microsoft Detours 内联 Hook 以下 Winsock 函数:
             │   ├─ connect       (TCP/UDP 连接)
             │   ├─ WSAConnect    (扩展连接)
             │   ├─ sendto        (UDP 发送)
             │   ├─ getaddrinfo   (DNS 解析, ANSI)
             │   └─ GetAddrInfoW  (DNS 解析, Unicode)
             └─ 每次网络调用: 匹配规则 → 放行 / 拦截
```

### 为什么使用 Detours 内联 Hook

主要目标程序 `opencode` 是 Go 应用。Go 在 Windows 上通过 `LoadLibrary("ws2_32.dll")` + `GetProcAddress` 在运行时动态获取 Winsock 函数指针，绕过了 IAT（导入地址表）。简单的 IAT Hook 无法拦截 Go 的网络调用。

Microsoft Detours 的内联 Hook 直接修改目标函数体的前几个字节，插入跳转指令。无论函数指针是怎么获取的，都会被拦截。

## 配置方式

### 方式一：config.ini

在 `config.ini` 中添加 `[NetworkFilter]` 段：

```ini
[App]
exe=opencode.exe
moniker=OpenCodeContainer
capabilities=internetClient
; ... 其他配置 ...

[NetworkFilter]
; 默认策略：当没有规则匹配时的行为
; allow = 放行（黑名单模式），block = 拦截（白名单模式）
defaultPolicy=block

; 连接规则（按顺序匹配，首个匹配的规则生效）
; 格式: action:protocol:host:port
;   action   = allow | block
;   protocol = tcp | udp | *
;   host     = IP地址 | CIDR段 (如 10.0.0.0/8) | *
;   port     = 端口号 | 端口范围 (如 80-443) | *
; 多条规则用分号分隔
connectRules=allow:tcp:*:443;allow:tcp:*:80;allow:*:*:53

; DNS 规则（按顺序匹配，首个匹配的规则生效）
; 格式: action:domain
;   action = allow | block
;   domain = 精确域名 | 通配符 (如 *.example.com) | *
; 多条规则用分号分隔
dnsRules=allow:api.anthropic.com;allow:*.github.com;allow:*.openai.com
```

### 方式二：命令行 `-n` 参数

```
AppContainer.exe -i opencode.exe -m OpenCodeContainer -c internetClient -n "block;allow:tcp:*:443;allow:*:*:53;dns:allow:api.anthropic.com"
```

`-n` 参数格式：`默认策略;规则1;规则2;...`

- 第一个分号前的部分是默认策略（`allow` 或 `block`）
- 以 `dns:` 开头的是 DNS 规则（自动去掉 `dns:` 前缀）
- 其余的是连接规则

## 规则详解

### 连接规则 (connectRules)

控制 `connect`、`WSAConnect`、`sendto` 等 Winsock 调用。

格式：`action:protocol:host:port`

| 字段 | 可选值 | 说明 |
|------|--------|------|
| action | `allow`, `block` | 放行或拦截 |
| protocol | `tcp`, `udp`, `*` | 协议类型，`*` 匹配任意协议 |
| host | IP, CIDR, `*` | 目标地址。支持单个 IP (`1.2.3.4`)、CIDR 段 (`10.0.0.0/8`)、`*` 匹配任意 |
| port | 数字, 范围, `*` | 目标端口。支持单个端口 (`443`)、范围 (`80-443`)、`*` 匹配任意 |

**示例：**

```ini
; 白名单模式：只允许 HTTPS、HTTP 和 DNS
connectRules=allow:tcp:*:443;allow:tcp:*:80;allow:*:*:53

; 黑名单模式：屏蔽内网
connectRules=block:*:10.0.0.0/8:*;block:*:172.16.0.0/12:*;block:*:192.168.0.0/16:*

; 只允许连接特定服务器
connectRules=allow:tcp:104.18.0.0/16:443;allow:tcp:140.82.112.0/20:443
```

### DNS 规则 (dnsRules)

控制 `getaddrinfo` 和 `GetAddrInfoW` 的 DNS 解析。

格式：`action:domain`

| 字段 | 可选值 | 说明 |
|------|--------|------|
| action | `allow`, `block` | 放行或拦截 |
| domain | 域名, 通配符, `*` | 支持精确匹配 (`api.anthropic.com`)、通配符 (`*.github.com` 匹配所有子域名及自身)、`*` 匹配任意 |

通配符 `*.example.com` 同时匹配 `example.com` 本身和所有子域名（如 `api.example.com`、`cdn.example.com`）。

**示例：**

```ini
; 只允许特定 API 域名解析
dnsRules=allow:api.anthropic.com;allow:*.github.com;allow:*.openai.com

; 屏蔽特定域名
dnsRules=block:evil.com;block:*.malware.org;block:*.tracking.net
```

### 规则匹配逻辑

1. 规则**按顺序**从前到后匹配
2. **首个匹配的规则**决定结果（allow 或 block）
3. 如果没有规则匹配，使用 `defaultPolicy`
4. IPv6 地址：当前不支持 IPv4 规则匹配 IPv6 地址，IPv6 连接直接使用 `defaultPolicy`

### 拦截行为

| 被 Hook 的函数 | 拦截时的错误码 |
|----------------|----------------|
| `connect` | `WSAEACCES` (10013) |
| `WSAConnect` | `WSAEACCES` (10013) |
| `sendto` | `WSAEACCES` (10013) |
| `getaddrinfo` | `WSAHOST_NOT_FOUND` (11001) |
| `GetAddrInfoW` | `WSAHOST_NOT_FOUND` (11001) |

## 日志

当启用日志 (`log=true` 或 `-g`) 时，NetFilter.dll 会在 launcher 日志目录下生成独立的日志文件，文件名格式：`LaunchAppContainer_YYYYMMDD_HHMMSSmmm_netfilter.log`。

日志记录每次网络调用的匹配结果：

```
[2026-02-14 15:30:01.123] NetFilter loaded: default=block, connectRules=3, dnsRules=2
[2026-02-14 15:30:01.124] Hooks installed: OK (err=0)
[2026-02-14 15:30:02.456] ALLOW DNS api.anthropic.com
[2026-02-14 15:30:02.789] ALLOW connect 104.18.32.7:443 (proto=tcp)
[2026-02-14 15:30:03.012] BLOCK DNS evil.com
[2026-02-14 15:30:03.345] BLOCK connect 10.0.0.1:8080 (proto=tcp)
```

## 典型使用场景

### 场景一：AI 工具白名单

只允许 opencode 访问必要的 API 端点：

```ini
[NetworkFilter]
defaultPolicy=block
connectRules=allow:tcp:*:443;allow:*:*:53
dnsRules=allow:api.anthropic.com;allow:*.github.com;allow:*.githubusercontent.com
```

### 场景二：屏蔽内网

允许所有外网访问，但禁止访问内网：

```ini
[NetworkFilter]
defaultPolicy=allow
connectRules=block:*:10.0.0.0/8:*;block:*:172.16.0.0/12:*;block:*:192.168.0.0/16:*;block:*:169.254.0.0/16:*
```

### 场景三：仅 HTTPS

只允许 HTTPS 和 DNS：

```ini
[NetworkFilter]
defaultPolicy=block
connectRules=allow:tcp:*:443;allow:*:*:53
dnsRules=allow:*
```

## 注意事项

- 需要为 AppContainer 授予网络 capability（如 `internetClient`），否则内核层面就会阻止所有网络。NetFilter 是在 capability 允许的基础上做进一步的细粒度控制。
- 如果未配置 `[NetworkFilter]` 段，不会注入 DLL，行为与之前完全一致（零开销）。
- 当前仅支持 IPv4 规则匹配。IPv6 连接使用 `defaultPolicy` 处理。
- NetFilter.dll 必须与 AppContainer.exe 放在同一目录下。

## 项目结构

```
AppContainer/
├── AppContainer.sln
├── AppContainer/
│   ├── AppContainer.vcxproj
│   └── AppContainer.cpp          # Launcher 主程序
├── Detours/
│   ├── Detours.vcxproj           # 静态库项目
│   ├── LICENSE.md                 # MIT License
│   └── src/                      # Microsoft Detours 源码
│       ├── detours.h
│       ├── detours.cpp
│       ├── modules.cpp
│       ├── disasm.cpp
│       ├── image.cpp
│       └── creatwth.cpp
└── NetFilter/
    ├── NetFilter.vcxproj          # DLL 项目
    └── NetFilter.cpp              # 网络过滤 DLL 实现
```

构建依赖：`Detours.lib` → `NetFilter.dll` + `AppContainer.exe`
