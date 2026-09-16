# 九号出行 App 云 API 逆向工程完整报告

> 版本：v1.1（终稿汇总 + 车辆接口复核增补）
> 汇总日期：2026-08-11
> 分析周期：2026-08-07（第一轮 ~ 第七轮）
> 分析对象：
> - 九号出行 Android APK（`cn.ninebot.ninebot` v6.x，小米应用商店官方直链，270,666,602 字节）
> - 第三方逆向工具 **ninecli v0.1.7**（PyPI/MIT，Go 实现，Linux x86_64 二进制 8.9MB）
> - 反汇编材料：`dis.txt`（objdump 全量反汇编 29MB）、`gore_out.json`（GoReSym 符号表 85MB）
> 目标：完整还原九号云 API 的认证、加密协议、全部接口报文格式，用于纯 Python 拉取历史行程并计算 App 隐藏的最高速 / 平均速。

---

## 0. 摘要

1. **APK 被梆梆（Bangcle）全量加固**，jadx 静态反编译只能看到 31 个壳桩类，业务代码不可见；真实算法从第三方 ninecli 二进制（Go 编写的九号 API 客户端）静态反汇编 + 动态取证还原。
2. **完整加密协议已还原到公式级**：Passport 签名（SHA256）、网易加密层（AES-128-CBC / RSA-1024 / MD5 / 自研 DeriveKey 密钥派生 / AndroidB64），全部经 unicorn 执行原始机器码 + GDB 断点抓包逐字节验证。
3. **全部接口端点、请求头、内层 JSON 字段顺序已确认**：Passport 登录/刷新、Business 登录、车辆列表、行程列表、行程详情。
4. **行程列表响应含最高速字段 `speed`**（服务端直接下发，无需计算）；平均速度 = 里程 ÷ 时长。
5. **交付纯 Python 客户端** `ninebot_api.py` + `ninebot_crypto.py`（零二进制依赖），`--self-test` 无账号全链路自测通过。

---

## 1. 分析对象与方法

### 1.1 APK 情况

| 项目 | 值 |
|---|---|
| 包名 | `cn.ninebot.ninebot` |
| 来源 | 小米应用商店（九号官网 `app.ninebot.com/downloads/v5/cn.html` 跳转） |
| 大小 | 270,666,602 字节（~258 MB） |
| dex | 单个 `classes.dex`，106 MB，标准 `dex\n035` 头 |
| 加固 | **梆梆安全（Bangcle）全量加固**：classes.dex 仅含 31 个桩类，真实业务代码运行时由 native 解密 |
| 关键 native 库 | `libencrypt.so`（含 `Java_com_bangcle_comapiprotect_CheckCodeUtil_checkcode` / `decheckcode`）、`libEncryptorP.so`、`libnesec.so`、`librust_lib.so` |

**结论**：当前版本 APK 纯静态反编译不可行。但 APK 中 `CheckCodeUtil.checkcode` 与 ninecli 重实现的 `crypto.ComputeCheckcode` 一一对应，即**请求校验码算法已被社区完整重实现**，云 API 侧可从 ninecli 二进制完整恢复。

### 1.2 分析工具链

| 工具 | 用途 |
|---|---|
| jadx | APK 反编译（确认加固） |
| GoReSym | 从 Go 二进制恢复 2338 个用户函数符号 + 类型元数据（`gore_out.json`） |
| objdump / capstone | 全量反汇编（`dis.txt` 29MB）、函数级指令提取（`disasm_func*.py`） |
| GDB | 断点抓寄存器/内存/实参（`gdb_*.gdb` 系列脚本），如 AES 入口抓 wrapper 明文、MD5 入口抓 checkcode 输入 |
| unicorn | 动态执行二进制原始机器码，交叉验证 Python 公式（DeriveKey 11 组 / AndroidB64 9 组 ALL PASS） |
| strace | 系统调用跟踪（安全审计） |
| 假服务器 | `fake_passport*.py` / `fake_server3/4.py`，记录真实请求路径与报文 |

### 1.3 VA ↔ 文件偏移换算

二进制段布局：`.text` VA 0x401000 ↔ 文件 0x1000；`.rodata` VA 0x7ee000 ↔ 文件 0x3ee000。

---

## 2. 系统架构总览

### 2.1 服务域名（5 个，全部为九号官方）

| 用途 | 默认地址 | 加密 |
|---|---|---|
| Passport 认证 | `https://api-passport-bj.ninebot.com` | 明文 + Sign 签名 |
| 业务登录（jhcx v6 北京） | `https://api-jhcx-v6-bj.ninebot.com` | 网易加密层 |
| 行程数据（CN CBU 网关） | `https://cn-cbu-gateway.ninebot.com` | 网易加密层 |
| 车辆列表/控制（电动自行车） | `https://ebike.ninebot.com` | 网易加密层 |
| 电机/其他 | `https://steeldust.ninebot.com` | 网易加密层 |

### 2.2 双层认证体系

```
┌────────────────────────────────────────────────────────────────┐
│ 第 1 层：Passport（明文 JSON + SHA256 Sign 签名）                │
│   POST /v6/user/login  →  access_token / refresh_token / uuid   │
└──────────────────────────────┬─────────────────────────────────┘
                               │ access_token
┌──────────────────────────────▼─────────────────────────────────┐
│ 第 2 层：Business（网易加密层，wire 层 D/H/K/P/T + wrapper）      │
│   POST /user/user/login    →  business_uid（内层 data.uid）      │
│   POST /vehicle/binding/my-vehicle  →  车辆列表（wnumber/SN）    │
│   POST /app-api/travel/v6/travel-list2  →  月度行程列表          │
│   POST /app-api/travel/v6/travel-info   →  单次行程详情          │
└────────────────────────────────────────────────────────────────┘
```

### 2.3 加密协议全景（"网易加密层"）

```
请求（wire 层）:
  {"d": b64(AES-128-CBC 密文), "h": md5hex(明文 wrapper), "k": b64(RSA-1024(AES密钥)),
   "p": "101", "t": "0"}

请求明文（wrapper JSON，h = md5 的对象）:
  {"data": AndroidB64(业务JSON), "keyDataOne": kd1, "keyDataTwo": kd2,
   "keyDataThree": kd3, "keyDataFour": kd4, "platform": 2, "timeStamp": <Unix秒>}

响应（wire 层）:
  {"r": b64(AES-128-CBC 密文)}
  → 解密密钥 = DeriveKey(kd1, kd2, kd3, kd4)（与请求 AES 密钥无关，第二把独立密钥）
  → 明文仍是 wrapper JSON → 取 data 字段 → AndroidB64 解码 → 业务 JSON

密钥材料:
  AESkey = GenKReq() = 16 字节随机（94 个可打印 ASCII 字符集）
          经 RSA-1024 公钥加密放进 k 字段传给服务器
  kd1..4 = GenKeyData() = randHex(11), randHex(11), randHex(10),
                          randFromCharset(8, 69 字符集)
          明文放进 wrapper，服务器用它派生响应加密密钥
```

---

## 3. Passport 认证协议（第 1 层，明文）

### 3.1 请求头

| 头 | 值 |
|---|---|
| `App_version` | `610063322` |
| `Clientid` | `vehicle_app_prod` |
| `Content-Type` | `application/json; charset=UTF-8` |
| `Os` | `Android` |
| `Os_language` | `zh-hans-cn` |
| `Os_version` | `13` |
| `Timestamp` | Unix 毫秒时间戳（与 Sign 内的 timestamp 相同） |
| `Sign` | SHA256 签名（见 3.3） |
| `Accept-Encoding` | `gzip` |

### 3.2 请求体（`POST /v6/user/login`）

```json
{"areaCode": "86", "device": "ANDROID", "password": "<密码>", "username": "<手机号/用户名>"}
```

### 3.3 Sign 签名算法（已端到端验证 ✅）

```python
import hashlib

CLIENT_KEY = "e177176a-3b3e-1513-e26e-d1123034cb66"   # 硬编码在二进制中

def passport_sign(url: str, params: dict) -> str:
    params = dict(params)
    params["clientKey"] = CLIENT_KEY    # 自动补 clientKey
    params["url"] = url                 # 自动补 url（接口路径）
    canonical = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
    return hashlib.sha256(canonical.encode()).hexdigest()
```

登录时 params 至少包含：`app_version, areaCode, clientKey, device, os, os_language, os_version, password, timestamp, url, username`。

**验证**：GDB 在 `crypto/sha256.Sum256` 断点抓到的 canonical 字符串，其 SHA256 结果与假服务器实际收到的请求头 `Sign` 完全一致。真实 canonical 样例：

```
app_version=610063322&areaCode=86&clientKey=e177176a-3b3e-1513-e26e-d1123034cb66&device=ANDROID&os=Android&os_language=zh-hans-cn&os_version=13&password=endtoendpw1&timestamp=1786095783403&url=/v6/user/login&username=e2etest
```

### 3.4 响应（成功，code=0）

```json
{
  "code": 0,
  "data": {
    "uuid": "<uuid>",
    "username": "<用户名>",
    "phone": "<手机号>",
    "region": "<region>",
    "access_token": "<access_token>",
    "refresh_token": "<refresh_token>",
    "accessTokenValidity": 1786xxxxxxx
  }
}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `code` | int | 0 = 成功；非 0 见 `msg` |
| `data.uuid` | string | 用户 UUID |
| `data.access_token` | string | Passport 访问令牌（business 请求头 `Access_token` + 内层 `access_token`） |
| `data.refresh_token` | string | 刷新令牌 |
| `data.accessTokenValidity` | number | 毫秒绝对过期时间戳（客户端据此判断是否需刷新/重登） |

### 3.5 刷新（`POST /v3/user/refresh`）

请求体：

```json
{"accessToken": "<access_token>", "device": "ANDROID", "refreshToken": "<refresh_token>"}
```

Sign 参数：`accessToken, app_version, device, os, os_language, os_version, refreshToken, timestamp, url`（同样自动补 `clientKey`）。

响应格式同 3.4，返回新 `access_token` / `refresh_token` / `accessTokenValidity`。

---

## 4. 网易加密层完整算法（第 2 层，公式级还原）

> 所有函数均已与二进制反汇编逐指令核对（17/18 一致，1 处 JSON 转义差异已修复），
> 核心公式经 unicorn 动态执行二进制机器码验证。纯 Python 实现见 `ninebot_crypto.py`。

### 4.1 函数清单与验证状态

| 函数 | 二进制地址 | 状态 | 验证方式 |
|---|---|---|---|
| `DeriveKey` | 0x6c99e0-0x6c9b80 | ✅ | 反汇编逐指令 + unicorn 11 组测试向量 |
| `AndroidB64` | 0x6c95a0-0x6c9840 | ✅ | 反汇编 + unicorn 9 组测试向量 |
| `GenKReq` | 0x6ca880-0x6ca9e0 | ✅ | 字符集/拒绝采样逐字节核对 |
| `GenNonce` | 0x6ca9e0-0x6cab20 | ✅ | 大小写规则逐指令核对 |
| `GenKeyData` | 0x6cab20-0x6cac40 | ✅ | 长度/字符集逐字节核对 |
| `randHex` | 0x6cad40-0x6caea0 | ✅ | 字符集 @VA + 拒绝采样边界 |
| `randFromCharset` | 0x6caea0-0x6cb020 | ✅ | 同上 |
| `ComputeCheckcode` | 0x6cac40-0x6cad40 | ✅ | GDB 抓小写 hex → ToUpper |
| `BuildWrapper` | 0x6cc4c0-0x6cc7a0 | ✅ | 全部 11 个字面量逐字节 + 字段序 |
| `jsonEscapeString` | 0x6cc7a0-0x6cc960 | ✅ | 5 个转义分支逐指令 |
| `BuildInner` | 0x6cece0-0x6cf0e0 | ✅ | GDB 抓 446B/493B 逐字节复现 |
| `EncryptRequest` | 0x6ca000-0x6ca300 | ✅ | GDB 抓 D/H/K/P/T 实锤 |
| `DecryptResponse` | 0x6ca300-0x6ca880 | ✅ | b64→DeriveKey→AESDecrypt→wrapper 解包 |
| `PassportSign` | — | ✅ | 第二轮端到端验证（见 §3.3） |

### 4.2 密钥材料生成

**GenKReq()** —— 请求 AES 密钥（16 字节）：
- 字符集 @VA 0x8f9864 = 94 个可打印 ASCII（`0x21`~`0x7e`）：
  ```
  !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~
  ```
- 16 次循环（`cmp $0x10,%rcx`），每次拒绝采样（bound=94，`cmp $0x5e,%rdx; jb` 循环）

**GenKeyData()** —— 4 个密钥分量（响应解密密钥派生用）：
- `kd1 = randHex(11)`（小写 hex，11 字符）
- `kd2 = randHex(11)`
- `kd3 = randHex(10)`
- `kd4 = randFromCharset(8, 69 字符集)`，字符集 @VA 0x8f6f46：
  ```
  abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789;-_.,+/
  ```

**GenNonce()** —— 内层 `nonce` 字段（32 位 hex）：
- `crypto/rand.Read` 16 随机字节 → hex 编码
- **首字节两个 hex 字符小写**（`cmp $0xa; jae +0x57`，`0x57` = 'a'-10），**其余 15 字节大写**（`+0x37` = 'A'-10）
- = Python `h[0:2].lower() + h[2:].upper()`
- 真实样例：`b180D2754AC8C4CFE7BFF4C0AD0F60F6`

**随机数**：拒绝采样（非取模），Python 侧用 `secrets.randbelow(bound)` 等价模拟。

### 4.3 DeriveKey 公式（响应解密密钥，已验证 ✅）

`DeriveKey(A, B, C, D []byte) [16]byte`，@0x6c99e0-0x6c9b80。
Go 内部 ABI 参数：`rax=A_ptr rbx=A_len rdi=B_ptr rsi=B_len r9=C_ptr r10=C_len`，D 走栈参数。

```python
def rol32(v, n):
    n %= 32
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

def rol8acc(s):                    # 每个输入的 ROL8 累加
    v = 0
    for b in s:
        v = rol32(v, 8) ^ b
    return v & 0xFFFFFFFF

A = rol8acc(a); B = rol8acc(b); C = rol8acc(c); D = rol8acc(d)
x = A ^ C;  y = B ^ D
fx = rol32(x, 8) ^ x ^ rol32(x, 24)
gy = rol32(y, 8) ^ y ^ rol32(y, 24)
a1 = A ^ gy;  b1 = B ^ fx;  c1 = C ^ gy;  d1 = D ^ fx
out3 = (c1 & b1) ^ a1
tmp  = ~(c1 ^ d1 ^ ((c1 | d1) ^ b1)) & 0xFFFFFFFF
out2 = out3 ^ tmp
out1 = ((tmp | out3) ^ ((c1 | d1) ^ b1)) & 0xFFFFFFFF
out0 = ((~((c1 | d1) ^ b1) & out2) ^ d1) & 0xFFFFFFFF
key  = struct.pack("<IIII", out0, out1, out2, out3)   # 4 个 dword 小端
```

**验证**：`verify_derivekey.py` 用 unicorn 直接执行二进制里 DeriveKey 的机器码（hook 唯一外部调用 0x478860 堆分配），11 组测试向量（空输入/单字节/二进制随机）与 Python 公式输出完全一致。

已知测试向量：
```
derive_key(b"abcdefghijklm", b"0123456789ab", b"XYZ", b"ninebot!")
  = 82ffe6a8cbb9a4ffdbf791a74e37176e
```

### 4.4 AndroidB64（已验证 ✅）

@0x6c95a0，模拟 Android `Base64.DEFAULT` 的**自研实现**：
- 标准 base64 编码（`0x4edce0` = base64.StdEncoding.EncodeToString，全局 0xc87c50）
- **每 76 字符插入 `\n`**（0x6c962e `lea 0x4c(%rcx),%rdi` = 76 边界）
- **非空时末尾恒有 `\n`**（0x6c9611/0x6c9609 路径）
- 空输入返回空串

```python
def android_b64(data: bytes) -> str:
    b = base64.b64encode(data)
    if not b:
        return ""
    lines = [b[i:i + 76] for i in range(0, len(b), 76)]
    return b"\n".join(lines).decode() + "\n"
```

**验证**：`verify_androidb64.py` unicorn 执行机器码，9 组长度（1/5/56/57/58/113/114/115 字节）全部一致。

### 4.5 JSON 转义规则（两套，容易搞混）

**jsonEscapeString @0x6cc7a0**（wrapper 的 data 字段值用）：
| 字符 | 输出 |
|---|---|
| `\t` (0x09) | `\t` |
| `\n` (0x0a) | `\n` |
| `\r` (0x0d) | `\r` |
| `"` (0x22) | `\"` |
| `\` (0x5c) | `\\` |
| 其他（含非 ASCII） | 原样 |
开头/结尾各补一个 `"`。**wrapper 的 data 是 AndroidB64 输出（含 `\n`），必须转义。**

**writeJSONValue @0x6cc0a0**（内层业务 JSON 字符串值用）：
- 同样**只转义 `\n \t \r " \` 五个字符**
- `<>&`、U+2028/U+2029、其他控制字符、非 ASCII **全部原样输出**（utf8.DecodeRune 后 append rune）
- **没有** Go `encoding/json` 默认的 HTML escape（`<`→`\u003c` 等）
- key 直接 append 不转义
- 紧凑输出、无空格、字段按声明顺序

> ⚠️ 这是第六轮逐句对照发现的**唯一差异**：初版 Python 实现按 Go `encoding/json` 默认行为多做 `<>&` 与 U+2028/2029 转义，已改为自定义编码器精确模拟（`_go_json_dumps`），GDB 抓包 446B 主体 + 493B 完整内层逐字节复现。

### 4.6 BuildWrapper —— 明文 wrapper（h = md5 的对象）

@0x6cc4c0，拼接顺序（lea 序列逐条确认，11 个字面量）：
```json
{
	"data" : "<jsonEscape(AndroidB64(业务JSON))>",
	"keyDataFour" : "<kd4>",
	"keyDataOne" : "<kd1>",
	"keyDataThree" : "<kd3>",
	"keyDataTwo" : "<kd2>",
	"platform" : 2,
	"timeStamp" : <Unix秒>
}
```

| 字面量 | VA | 说明 |
|---|---|---|
| `{\n` | 0x8d79a2 | 开头 |
| `\t"data" : ` | 0x8d9e2d | data 键 |
| `,\n` | 0x8d79a4 | 分隔 |
| `\t"keyDataFour" : "` | 0x8de1d1 | kd4 键 |
| `",\n` | 0x8d7b4b | 分隔 |
| `\t"keyDataOne" : "` | 0x8dd7ec | kd1 键 |
| `\t"keyDataThree" : "` | 0x8deb4c | kd3 键 |
| `\t"keyDataTwo" : "` | 0x8dd7fd | kd2 键 |
| `\t"platform" : ` | 0x8dbeed | platform（十进制） |
| `\t"timeStamp" : ` | 0x8dc544 | timeStamp（十进制） |
| `\n}\n` | 0x8d7b4e | 结尾 |

- **字段顺序固定**：data → keyDataFour → keyDataOne → keyDataThree → keyDataTwo → platform → timeStamp
- **platform**：business 域统一 = 2（登录/vehicles/travel 全为 2；通用层默认 10 = Android，调用方传入）
- **timeStamp**：business 域 = **Unix 秒**（0x6cf423 `movabs $0xfffffff1886e0900` = -62135596800 秒偏移 + time.Now()）
- **毫秒只在**内层 CommonParams 的 `serviceTime` 字段用（0x6cf2a4 `imul $0x3e8`）

**真实抓包样例**（travel-list 请求明文，916B）：
```json
{
	"data" : "eyJzeXNfbGFuZ3VhZ2UiOiJ6aC1oYW5zLWNuIiwiY2xpZW50X3ZlciI6IjYxMDA2MzMyMiIsImRl\ndmljZV9pZCI6...In0=\n",
	"keyDataFour" : "SPM;Vf-l",
	"keyDataOne" : "f5785dd42f9",
	"keyDataThree" : "62ce9206e8",
	"keyDataTwo" : "3a3c424c87d",
	"platform" : 2,
	"timeStamp" : 1786103807
}
```
（data 字段 base64 解码后即 §5.4 的内层 JSON，含 checkcode。）

### 4.7 BuildInner + ComputeCheckcode —— 内层业务 JSON

@0x6cece0 / @0x6cac40：

1. 按**字段声明顺序**（Go struct 序列化，非 map 字母序）构造紧凑 JSON 主体
2. `checkcode = MD5(主体).hexdigest().upper()`（MD5 @0x5d1780，hex 用小写字符集 0x8dc865 → `strings.ToUpper` @0x4f3dc0）
3. 拼接：`主体去掉结尾 }` + `,"checkcode":"<cc>"}`（0x8dbca1 = `,"checkcode":"` len 14）

```python
def build_inner(params: dict) -> str:
    params = dict(params)
    inner_no_cc = _go_json_dumps(params)                       # 无 checkcode
    checkcode = hashlib.md5(inner_no_cc.encode()).hexdigest().upper()
    params["checkcode"] = checkcode
    return _go_json_dumps(params)                              # 含 checkcode（恒在最后）
```

**注意**：`checkcode` 的 MD5 输入是**无 checkcode 的内层紧凑 JSON**（不是 wrapper！）。真实样例验证：
```
输入: {"sys_language":"zh-hans-cn",...,"nonce":"226C2445588BBA9A0733990055675691"}
checkcode = 61FF687766285F413F08ECB596B6C9F6
复算 MD5(输入) = 61FF687766285F413F08ECB596B6C9F6 ✅
```

### 4.8 EncryptRequest —— wire 层 D/H/K/P/T

@0x6ca000，流程：

1. `GenKReq()` 生成 16 字节随机 AES 密钥
2. `GenKeyData()` 生成 4 个密钥分量 kd1..4
3. 拼 wrapper 明文（§4.6）
4. `d = b64(AES-128-CBC(wrapper))` —— **IV = 16 个零字节**（0x6ccbcc 分配清零缓冲区直接作 IV），PKCS7 pad
5. `h = md5hex(wrapper)`（**小写** hex；0x8dc865 字符集）
6. `k = b64(RSA-1024(AESkey))` —— `crypto/rsa.EncryptPKCS1v15` @0x5cc120，公钥全局 0xc87c00（= init.0 解析的 N1）
7. `p = "101"`、`t = "0"` —— 来自 0x998070 静态模板（80B memmove @0x47eb1a 初始化返回结构体，GDB 实锤）

```json
{
  "d": "<base64: AES-128-CBC 密文>",
  "h": "<32位小写hex: MD5(wrapper)>",
  "k": "<base64: RSA-1024(AES密钥)>",
  "p": "101",
  "t": "0"
}
```

**GDB 实锤样例**（EncryptRequest 返回结构体 0x6ca260，rsp+0x160 起 0x50 字节）：
```
D = 'QNREyiUkEozAKXrOWIfFAtdQk32Dl0kGbXz6xSqnieDD...'  ← b64(AES-CBC(wrapper))
H = 'd8b579b27fecf221d7d7e3d63481b5f4'                  ← md5hex(wrapper) 小写
K = 'WGnwA/FFc1MW01c3vxRkhee/42rUYrjwV38/PVRIBxR7gR30...' ← b64(RSA-1024(AESkey))
P = '101'
T = '0'
```

### 4.9 DecryptResponse —— 响应解密（含 wrapper 解包）

@0x6ca300，流程：

1. `base64 decode` r（`decrypt failed: base64 r:` 错误路径 @0x4ee2e0）
2. `key = DeriveKey(kd1, kd2, kd3, kd4)`（0x6ca4ad call 0x6c99e0；参数顺序 rax/rbx=kd1, rdi/rsi=kd2, r9/r10=kd3, 栈=kd4）
3. `AESDecrypt`（0x6ca4d3 call 0x6ccce0，IV=0）→ `PKCS7Unpad`（@0x6cc960）
4. **解密明文是 wrapper JSON**（`{"data": AndroidB64(业务JSON), "platform": 2, "timeStamp": <秒>}`）
5. `unescapeJSONString` 取 `data` 字段 → **AndroidB64 解码** → 业务 JSON
   （错误串 `decrypt failed: missing 'data' field in wrapper` 证实响应也是 wrapper 封装）

> ⚠️ 第七轮修正：响应不是"裸业务 JSON 加密"，而是 **wrapper 再包一层**。客户端需解两层。

```python
def decrypt_wire_response(resp_body: dict, secrets) -> bytes:
    plain = decrypt_response(resp_body["r"], secrets["kd1"], secrets["kd2"],
                             secrets["kd3"], secrets["kd4"])
    return unwrap_response(plain)   # wrapper → data → AndroidB64 解码
```

### 4.10 两把独立密钥

| 方向 | 密钥 | 传递方式 |
|---|---|---|
| 请求加密 d | GenKReq 16 字节随机 | `k` = RSA-1024(AES key) b64 |
| 响应加密 | DeriveKey(kd1,kd2,kd3,kd4) | 服务器从明文 wrapper 的 keyDataOne..Four 取分量 |

### 4.11 RSA 公钥（两把，注意区分）

二进制中有**两把 RSA-1024 公钥**：

| 密钥 | 值前缀 | 位置 | 状态 |
|---|---|---|---|
| **N1** | `d3de6d1c...` | DER SPKI @VA 0xc2e020（140B） | ✅ **真实使用的**：crypto.init.0 @0x6c9b92 解析并缓存到 0xc87c00，EncryptRequest @0x6ca193 取用 → rsa.EncryptPKCS1v15（GDB 抓实参确认 N=rsa_n_1.bin） |
| N2 | `ba99a158...` | PEM 字符串 @VA 0xc2fae5（266B） | ❌ **死数据**：全文搜索无任何 (ptr,len) 字符串头 / RIP 引用指向它（旧版遗留） |

N1 PEM（真实使用）：
```
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDT3m0c/8y9c13PzaFbATEg+Zwd
kpPcCy0V21VKBBSx16ckVtLERAQ7EH8d6DqgEbyzayAwlQd1gDhUmx27hDWafXr9
/evUZkkBegcsNnKrIlh93lPKccjk+LDXS1TnDIIFiTlSbNnaYwehI/9pUbKCI3h7
yE0pum6hJh/9QtGPlwIDAQAB
-----END PUBLIC KEY-----
```

---

## 5. API 端点详表（路径 / 方法 / 请求头 / 报文 / 字段说明）

### 5.1 请求头（business 域，16 个）

```
User-Agent: okhttp/4.9.1
Business-Type: 0 | 2          # 0=未认证(登录)，2=已认证(vehicles/travel)
Client-Ver: 610063322
Content-Type: text/html;charset=UTF-8
Debug: 0
Device-Id: <32位hex，config.json device_id>
Language: zh
Login-Country: CN
Need_decrypt: 1                # 加密开关
Ninebot-Version: 2
Platform: Android
Platform-Ver: 13
Regionx: bj
Request-Id: <32位hex，每次随机>
Service-Time: <毫秒时间戳>
Sys-Language: zh-hans-cn
```

认证后（Business-Type:2）追加：

```
Access_token: <passport access_token>
Accept: application/json
Rn-Module: Track
Rn-Ver: 743
Rn-Version: 0
```

### 5.2 公共内层参数（11 字段，所有 business 请求一致，顺序固定）

```json
{
  "sys_language": "zh-hans-cn",
  "client_ver": "610063322",
  "device_id": "<32位hex>",
  "regionx": "bj",
  "language": "zh",
  "ostype": "and",
  "lang": "zh",
  "platform_ver": "13 Xiaomi",
  "platform": "android",
  "login_country": "CN"
}
```

| 字段 | 值 | 说明 |
|---|---|---|
| `sys_language` | `zh-hans-cn` | 系统语言 |
| `client_ver` | `610063322` | App 版本号（与请求头 Client-Ver / current_version 相同） |
| `device_id` | 32 位 hex | 设备 ID（config.json，首次自动生成） |
| `regionx` | `bj` | 区域（北京） |
| `language` | `zh` | 语言 |
| `ostype` | `and` | 操作系统类型 |
| `lang` | `zh` | 语言（重复字段，协议如此） |
| `platform_ver` | `13 Xiaomi` | = os_version + " " + os_model |
| `platform` | `android` | 平台 |
| `login_country` | `CN` | 登录国家 |

每类请求再追加专属字段 + `checkcode`（恒在最后，MD5 大写 hex，见 §4.7）。

### 5.3 `POST /user/user/login` —— business 登录（api-jhcx-v6-bj.ninebot.com）

**用途**：用 passport access_token 换取 business_uid（内层 data.uid），后续请求的 `uid` 字段。

**内层 JSON**（公共 11 字段 + 以下 7 字段 + checkcode，共 18 字段；真实抓包 446B）：

```json
{
  "sys_language": "zh-hans-cn", "client_ver": "610063322", "device_id": "<32hex>",
  "regionx": "bj", "language": "zh", "ostype": "and", "lang": "zh",
  "platform_ver": "13 Xiaomi", "platform": "android", "login_country": "CN",
  "access_token": "<passport access_token>",
  "uuid": "<passport uuid>",
  "token": "<passport access_token>",
  "refresh_token": "<passport refresh_token>",
  "region": "bj",
  "serviceTime": 1786103097851,
  "nonce": "b180D2754AC8C4CFE7BFF4C0AD0F60F6",
  "checkcode": "<32位大写hex>"
}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `access_token` | string | passport access_token |
| `uuid` | string | passport 返回的 uuid |
| `token` | string | 与 access_token 相同（协议冗余） |
| `refresh_token` | string | passport refresh_token |
| `region` | string | `bj` |
| `serviceTime` | number | **毫秒**时间戳（唯一用毫秒的内层字段） |
| `nonce` | string | 32 位 hex，首字节小写其余大写（§4.2） |
| `checkcode` | string | MD5(无 checkcode 的紧凑 JSON).upper() |

**业务响应**（解密后内层）：
```json
{
  "code": 0,
  "data": {"uid": "<business_uid>"},
  "message": ""
}
```
`data.uid` 即 business_uid，写入 tokens.json 供后续请求 `uid` 字段使用。

### 5.4 `POST /app-api/travel/v6/travel-list2` —— 月度行程列表（cn-cbu-gateway.ninebot.com）

> ⚠️ 路径**带 `2`**（`travel-list2`，31 字节）！初版文档误写为 `travel-list`（无 2），fake 服务器记录真实请求路径实锤。反汇编证据：`Business.Travel` @0x6d3011 `lea rdi,[rip+0x21365a]` → rodata 0x8e6672，`esi=0x1f`(31)。方法为 **POST**（初版文档的 GET 是错的）。

**内层 JSON**（公共 11 字段 + 以下 9 字段 + checkcode，共 20 字段；真实抓包样例）：

```json
{
  "sys_language": "zh-hans-cn", "client_ver": "610063322", "device_id": "ea86e19c33c5f291323fae270f5fea10",
  "regionx": "bj", "language": "zh", "ostype": "and", "lang": "zh",
  "platform_ver": "13 Xiaomi", "platform": "android", "login_country": "CN",
  "access_token": "FAKE_ACCESS_TOKEN_456",
  "uid": "FAKE_BIZ_UID_789",
  "wnumber": "NB1234567890",
  "rnVersion": "743",
  "vehicle_type": "112",
  "month": "202608",
  "page": "1",
  "current_version": "610063322",
  "serviceTime": 1786103807064,
  "nonce": "226C2445588BBA9A0733990055675691",
  "checkcode": "61FF687766285F413F08ECB596B6C9F6"
}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `access_token` | string | passport access_token |
| `uid` | string | business_uid（§5.3 获取） |
| `wnumber` | string | 车辆 SN（来自 vehicles 列表） |
| `rnVersion` | string | `743`（0x8d7b06 `743112` 硬编码的前 3 字节） |
| `vehicle_type` | string | `112`（电动自行车/行程域；vehicles 请求用 `64`） |
| `month` | string | `YYYYMM`，如 `202608` |
| `page` | string | 页码，`1` |
| `current_version` | string | `610063322` |
| `serviceTime` | number | 毫秒时间戳 |
| `nonce` | string | 32 位 hex |
| `checkcode` | string | MD5 大写 hex |

**业务响应**（解密 + wrapper 解包后，内层 `data`）：

```json
{
  "code": 0,
  "data": {
    "list": [
      {
        "travel_id": "<id>",
        "end_time_format": "2026-08-01 08:30:00",
        "mileages": "12.5",
        "duration": 1800,
        "speed": "45.2",
        "used_electricity": "8"
      }
    ],
    "total_mileages": "123.4",
    "ec": "...",
    "used_electricity": 8
  },
  "message": ""
}
```

**列表条目字段**（printTravelGroups.func1 @0x796ae0 反汇编确认）：

| 字段 | 类型 | 说明 |
|---|---|---|
| `travel_id` | string | 行程 ID（详情接口入参） |
| `end_time_format` | string | `"2026-08-01 08:30:00"`；二进制取 `[11:16]` 显示 HH:MM |
| `mileages` | **string** | 里程 km（ParseFloat 后使用） |
| `duration` | number | 时长秒 |
| `speed` | **string** | **最高速度 km/h**（ParseFloat；App 列表显示的就是它） |
| `used_electricity` | **string** | 耗电 %（ParseFloat） |

**汇总行**（二进制分组显示逻辑）：mileages 总和 / duration 总和 / **speed 取最大** / used_electricity 总和。

> 结论：**最高速度服务端直接下发**（字段名 `speed`，不是 `max_speed`），无需计算；平均速度 = mileages ÷ (duration/3600)。

### 5.5 `POST /app-api/travel/v6/travel-info` —— 单次行程详情（cn-cbu-gateway.ninebot.com）

反汇编证据：`Business.TravelDetail` @0x6d383a `lea rdi,[rip+0x212320]` → rodata 0x8e5b61，`esi=0x1e`(30)，路径 30 字节。方法为 **POST**（动态抓包确认；初版文档的 GET 是错的）。

**内层 JSON**（公共 11 字段 + 以下 8 字段 + checkcode，共 19 字段）：

```json
{
  "sys_language": "zh-hans-cn", "client_ver": "610063322", "device_id": "<32hex>",
  "regionx": "bj", "language": "zh", "ostype": "and", "lang": "zh",
  "platform_ver": "13 Xiaomi", "platform": "android", "login_country": "CN",
  "access_token": "<access_token>",
  "uid": "<business_uid>",
  "wnumber": "<车辆SN>",
  "rnVersion": "743",
  "vehicle_type": "112",
  "travel_id": "<行程ID>",
  "current_version": "610063322",
  "serviceTime": 1786103807064,
  "nonce": "<32hex>",
  "checkcode": "<32位大写hex>"
}
```

| 字段 | 说明 |
|---|---|
| `travel_id` | 行程 ID（列表响应 `travel_id` 原样传入） |
| 其余字段 | 同 §5.4（无 `month`/`page`，多 `travel_id`） |

**业务响应**（解密 + 解包后内层 `data`）：含 `travel_details`（逐点轨迹/速度数据）、起止时间（CST）、时长秒数。逐点字段名以实际返回为准（第七轮遗留：printTravelDetail @0x7960a0 未细挖）。

### 5.6 `POST /vehicle/binding/my-vehicle` —— 车辆列表（ebike.ninebot.com）

> ⚠️ 主机是 **ebike.ninebot.com**（不是 cbu-gateway）！GDB 抓包实测。business_line 判定：`ebike`→ebike 主机、`motor`→steeldust（travel 命令只接受这两种，否则 "unknown business line"）。

**内层 JSON**（公共 11 字段 + 以下 5 字段 + checkcode，共 16 字段）：

```json
{
  "sys_language": "zh-hans-cn", "client_ver": "610063322", "device_id": "<32hex>",
  "regionx": "bj", "language": "zh", "ostype": "and", "lang": "zh",
  "platform_ver": "13 Xiaomi", "platform": "android", "login_country": "CN",
  "access_token": "<access_token>",
  "uid": "<business_uid>",
  "vehicle_type": "64",
  "serviceTime": 1786103097851,
  "nonce": "<32hex>",
  "checkcode": "<32位大写hex>"
}
```

| 字段 | 说明 |
|---|---|
| `vehicle_type` | `64`（GDB 抓包实测；初版 Python 默认 65 已改 64） |

**业务响应**（内层 `data`）：车辆数组（`vehicles` 或 `list` 字段），每辆含 `wnumber`（= SN）、`vehicle_name`、`device_name`、`business_line` 等。

**反汇编证据（2026-08-11 复核）**：

```
### Business.Vehicles 0x6d3f00-0x6d4630（GoReSym 符号 + objdump 逐指令）
6d3f53: lea    0x20f944(%rip),%rdi        # 0x8e389e   ← 路径 rodata
6d3f5a: mov    $0x1b,%esi                              ← 0x1b = 27 = len("/vehicle/binding/my-vehicle")
6d3f73: call   0x6cf0e0                                ← api.BuildInner（构造内层 JSON + checkcode）
...
6d4108: lea    0x215152(%rip),%rax        # 0x8e9261   ← "vehicles: server code=%v message=%q"（错误串，证实函数语义）
6d427a: lea    0x215b40(%rip),%rax        # 0x8e9dc1   ← "vehicles: data[%d] is %T, not object"（响应解析）
6d43e0: lea    0x2143c0(%rip),%rdi        # 0x8e87a7   ← 同函数内第二个 BuildInner：/vehicle/vehicle/desktop-component
6d43e7: mov    $0x22,%esi                              ← 0x22 = 34 = len("/vehicle/vehicle/desktop-component")
```

- rodata `0x8e389e` 实存字节 `b'/vehicle/binding/my-vehicle'`（27B）✓
- rodata `0x8e87a7` 实存字节 `b'/vehicle/vehicle/desktop-component'`（34B）✓（另一接口，未细挖）
- 响应字段名 rodata 实证：`wnumber` @0x80440a、`vehicle_name` @0x8da8f8、`vehicles` @0x8d8bb2 等多处

**多车绑定与按车抓行程**（官方 App 支持绑定多辆，行程按车隔离）：

```
fetch_trips.py 流程：
  api.vehicles() ──► 所有绑定车 [{wnumber(SN), vehicle_name, ...}]
                          │  对每辆车各自：
                          ▼
  api.travel_list(wnumber=SN, month)  ──► 该车某月行程列表（内层含 wnumber 字段）
                          │
                          ▼
  api.travel_detail(wnumber=SN, travel_id)  ──► 该车某次行程详情
  缓存隔离：cache/travel_{SN}_{ym}.json、cache/detail_{SN}_{travel_id}.json
```

`travel-list2` / `travel-info` 内层 JSON 均携带 `wnumber`（车辆 SN）字段，服务器按车返回数据，互不混淆；`fetch_trips.py` 的 `get_vehicles()` 已实现遍历全部绑定车抓取。

### 5.7 其他已确认但未细挖的端点

| 端点 | 主机 | 说明 |
|---|---|---|
| `POST /v6/user/login/v4/code/phone` | api-passport-bj | 发送短信验证码（请求体含 checkcode 字段） |
| `POST /v6/user/phoneCodeLogin` | api-passport-bj | 验证码登录 |
| `POST /v5/user` | api-passport-bj | whoami / 校验 token |
| `GET /v6/vehicle/battery-info` | cn-cbu-gateway | 电池信息（字符串池确认） |
| `POST /vehicles/{sn}/engine/start` / `stop` | ebike.ninebot.com | 车辆控制（用户明确不需要，未细挖） |
| `open_buck`（开座桶）、`bell`（响铃） | ebike.ninebot.com | 控制命令（存在但未展开） |

> 注意：`GET /vehicles/{sn}/travel/{detail_id}` 是 ninecli `serve` 的**本地 REST 路由**（:18009 明文代理），不是九号 API 路径，勿混淆。

---

## 6. 端到端请求示例（纯 Python，完整流程）

```bash
# 1. 登录（passport + business，保存 tokens.json）
python3 ninebot_api.py login -u <手机号> -p <密码>

# 2. 车辆列表（拿 SN / wnumber）
python3 ninebot_api.py vehicles

# 3. 月度行程列表 / 单次详情
python3 ninebot_api.py travel <SN> --month 202608
python3 ninebot_api.py travel <SN> --detail <travel_id>

# 4. 全量抓取 + 计算最高速/平均速 + 输出 trips.json / trips.csv
python3 fetch_trips.py --from 202201 --to 202608

# 5. 无账号自测（验证签名/加密/解密全链路）
python3 ninebot_api.py --self-test
python3 ninebot_crypto.py          # 加密层自检（round-trip）
```

---

## 7. 验证记录汇总

| 验证项 | 方法 | 结果 |
|---|---|---|
| Passport Sign | GDB sha256 断点抓 canonical vs 假服务器收到的 Sign 头 | 完全一致 ✅ |
| DeriveKey | unicorn 执行二进制机器码，11 组测试向量 | ALL PASS ✅ |
| AndroidB64 | unicorn 执行二进制机器码，9 组长度 | ALL PASS ✅ |
| BuildInner | GDB 抓 446B（login）/493B（完整内层）逐字节比对 | 100% 复现 ✅ |
| BuildWrapper | GDB 抓 862B/916B wrapper 明文（含 kd1..4 真实值） | 逐字节一致 ✅ |
| EncryptRequest | GDB 抓返回结构体 D/H/K/P/T | 实锤 ✅ |
| 响应链路 | 假服务器构造合法加密响应（DeriveKey 复算），二进制正常解密 | 全链路跑通 ✅ |
| 加密层 vs 二进制 | 18 个函数逐句对照 | 17/18 一致，1 处 JSON 转义差异已修复 ✅ |
| 安全审计 | GoReSym + objdump + strace + 假服务器 | 无恶意代码 ✅ |

第九轮全链路输出样例（假服务器，二进制真实执行）：
```
08/01  1 rides  12.5km  1800s  max 45.2km/h  8% used
```

---

## 8. 安全审计摘要（详见 docs/security-audit.md）

- **结论：未发现恶意代码**。行为与声称一致：调用九号官方云 API 读取车辆信息与骑行历史。
- 无 `os/exec`、无 `plugin` 动态加载、无第三方网络端点（仅 5 个九号官方域名）、无硬编码 IP。
- strace 动态验证：登录仅连接假服务器 + DNS，仅写 token 文件（0600，先 .tmp 后原子重命名）。
- 风险提示：密码明文出现在 Passport 请求体（协议本身如此）；含车辆控制命令（建议只读使用）；PyPI 包匿名发布（建议固定 0.1.7 已审计版本）。
- **用户侧风险**：登录行为可能使手机端 App 会话失效（重新登录手机端即可恢复）；建议仅对本人账号操作，遵守九号服务条款，数据仅自用。

---

## 9. 交付物清单

| 文件 | 说明 |
|---|---|
| `ninebot_crypto.py` | 网易加密层纯 Python 实现（DeriveKey/AndroidB64/GenKReq/GenKeyData/GenNonce/BuildWrapper/BuildInner/EncryptRequest/DecryptResponse，含自检） |
| `ninebot_api.py` | 纯 Python API 客户端（passport 登录/刷新、business 登录、vehicles、travel-list/info，`--self-test`） |
| `fetch_trips.py` | 全量抓取 + 速度计算 + cache 断点续传 + trips.json/trips.csv 输出 |
| `docs/api-recon.md` | 逆向过程报告（分轮次） |
| `docs/crypto-vs-disasm.md` | 加密层与二进制逐句对照报告 |
| `docs/security-audit.md` | 安全审计报告 |
| `verify_derivekey.py` / `verify_androidb64.py` / `verify_buildwrapper.py` | unicorn 动态验证脚本 |
| `dump_crypto_funcs.py` + `dump_crypto.txt` | 18 个 crypto/api 函数反汇编 dump |
| `gdb_*.gdb` 系列 | GDB 断点取证脚本 |
| `disasm_func*.py` | 反汇编辅助工具 |

---

## 10. 已知遗留与风险

1. **真实服务器端到端未测**：全部验证基于假服务器 + GDB 抓包 + unicorn；登录真实账号后如遇响应解密异常，优先检查 wrapper 解包层（§4.9）。
2. **行程详情字段**（`travel-info` 响应的 `travel_details` 逐点结构）未细挖：printTravelDetail @0x7960a0 未展开；归一化脚本 `fetch_trips.py` 用候选字段名（`speed_list`/`track`/`points` 等）兼容，真实数据到位后按实际字段微调。
3. **float 格式理论差异**：二进制用 strconv 'f'，Python 用 repr；业务参数无 float，无实际影响。
4. **登录会顶掉手机端会话**（九号侧单会话策略），操作前知悉。
