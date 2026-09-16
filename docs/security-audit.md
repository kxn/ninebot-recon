# ninecli 二进制安全审计报告

审计对象：`ninecli_wheel/ninecli/bin/ninecli`（ninecli 0.1.7，Linux x86_64，8.9MB）
审计方法：静态分析（GoReSym 类型/函数恢复 + objdump 反汇编 + 字符串交叉引用）+ 动态验证（strace 系统调用跟踪 + 本地假服务器抓包 + GDB 断点取证）
审计时间：2026-08-07

## 结论

**未发现恶意代码。** 该二进制行为与其声称的功能一致：调用九号官方云 API 读取车辆信息与骑行历史。
未发现凭据外传、数据回传第三方、隐藏下载执行、命令注入、提权等恶意行为。

## 一、静态审计

### 1.1 函数清单（GoReSym 恢复 2338 个用户函数）

包结构完全符合开源 CLI 的常规布局，无混淆、无加密壳、无反调试：

| 包 | 职责 |
|---|---|
| `gitea.com/ninebot/cli/cmd` | cobra 命令行入口 |
| `gitea.com/ninebot/cli/internal/api` | 云 API 客户端（Passport 认证 + Business 业务） |
| `gitea.com/ninebot/cli/internal/crypto` | 网易加密层（AES/RSA/MD5/checkcode） |
| `gitea.com/ninebot/cli/internal/config` | 配置与 token 存储 |
| `gitea.com/ninebot/cli/internal/proxy` | 本地 HTTP 代理（serve 命令） |
| `gitea.com/ninebot/cli/internal/mcp` | MCP 服务器 |

### 1.2 危险系统调用检查（标准库引用扫描）

| 检查项 | 结果 |
|---|---|
| `os/exec`（命令执行） | ✅ 无 |
| `plugin.`（动态加载） | ✅ 无 |
| `syscall.Exec/ForkExec` | ✅ 无 |
| `syscall.Mount/Reboot` | ✅ 无 |
| `os.Setuid/Setgid/Chown` | ✅ 无 |
| `archive/zip`、`archive/tar`（自解压） | ✅ 无 |
| `os.Remove` | 仅 1 处（token 写入前的旧文件清理） |
| `os.ReadFile/WriteFile` | 各 2/1 处（config/tokens 读写，正常） |
| 加密原语 DES/RC4/MD5 | 均为标准库内部实现（TLS 兼容套件），业务代码未直接调用 |
| 业务实际使用 | AES-128-CBC、RSA-1024、SHA256、MD5（加密层必需） |

### 1.3 网络端点白名单

二进制中所有 URL 提取结果——**除 5 个九号官方域名外，无任何其他网络端点**：

```
https://api-passport-bj.ninebot.com   （Passport 认证）
https://api-jhcx-v6-bj.ninebot.com    （业务）
https://cn-cbu-gateway.ninebot.com    （行程）
https://ebike.ninebot.com             （车辆控制）
https://steeldust.ninebot.com         （电机/控制）
```
（其余 URL 均为第三方库错误信息中的链接：json-schema.org、github issues、go.dev，非网络端点。）

无硬编码 IP 地址。

### 1.4 字符串池审查

提取全部字符串（GoReSym + strings），发现的字段名、接口路径、请求头均为九号 API 业务所需，
无 base64 隐藏载荷、无编码混淆的 URL、无 shell 命令字符串。

## 二、动态审计（strace + 假服务器）

### 2.1 strace 系统调用跟踪（登录流程）

```
网络连接：
  connect(127.0.0.1:18080)   ← 仅连接我们指定的假 Passport 服务器
  connect(10.10.10.10:53)    ← DNS 解析（business host，正常流程）
文件操作：
  openat(/tmp/nb_audit/tokens.json.tmp, O_WRONLY|O_CREAT, 0600)  ← 仅写 token 文件
```

**无任何第三方出站连接，无敏感文件读取。**

### 2.2 假服务器抓包（登录请求全貌）

CLI 登录时只向指定 Passport 端点发送 1 个请求 `POST /v6/user/login`，请求体：
```json
{"areaCode":"86","device":"ANDROID","password":"<密码>","username":"<用户名>"}
```
密码明文只出现在发往 Passport 端点的请求体内（与九号官方协议一致），无旁路发送。

### 2.3 token 文件权限

`tokens.json` 写入权限 0600，先写 `.tmp` 再原子重命名——符合安全实践。

## 三、GDB 断点取证

对 `sha256.Sum256` 下断点，抓取签名输入，并与实际发出的请求头 `Sign` 对比：

```
canonical = app_version=610063322&areaCode=86&clientKey=e177176a-3b3e-1513-e26e-d1123034cb66&
            device=ANDROID&os=Android&os_language=zh-hans-cn&os_version=13&password=endtoendpw1&
            timestamp=1786095783403&url=/v6/user/login&username=e2etest
sha256(canonical) == 请求头 Sign  ✅ 完全一致
```

证明该二进制实现的就是标准 Passport 签名，无夹带私货。

## 四、风险提示（非恶意，但需知悉）

1. **闭源**：仓库 `gitea.com/ninebot/cli` 私有（404），无源码可审查，只能基于二进制审计。
2. **凭据处理**：登录时密码会明文出现在 Passport 请求体（协议本身如此）；token 明文存于
   `~/.config/ninebot/tokens.json`（0600）。
3. **功能超出需求**：除读取外，还包含 `engine-start/stop`、`buck`（开座桶）、`bell`（响铃）等
   车辆控制命令——建议使用时只调用读取类命令（vehicles/travel/status/battery）。
4. **更新不可控**：PyPI 包由"ninecli contributors"匿名发布，版本更新无法验证其内容是否变化。
   建议固定使用已审计的 0.1.7 版本二进制。

## 五、结论

该二进制可以安全地用于读取九号车辆数据；建议以只读命令使用、固定版本、妥善保管 token 文件。
