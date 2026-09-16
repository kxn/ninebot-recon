# 九号出行 App 云接口静态逆向分析报告

> 分析日期：2026-08-07
> 分析对象：九号出行 Android APK（`cn.ninebot.ninebot`，v6.x，小米应用商店官方直链 258MB）+ 第三方逆向工具 ninecli v0.1.7（MIT，Go 实现）二进制
> 目标：获取历史行程列表与单次行程详情接口，用于计算 App 隐藏的最高速度 / 平均速度

---

## 1. APK 情况

| 项目 | 值 |
|---|---|
| 包名 | `cn.ninebot.ninebot` |
| 来源 | 小米应用商店（九号官网 `app.ninebot.com/downloads/v5/cn.html` 跳转） |
| 大小 | 270,666,602 字节（~258 MB） |
| dex | 单个 `classes.dex`，106 MB，标准 `dex\n035` 头 |
| 加固 | **梆梆安全（Bangcle）全量加固**：classes.dex 仅含 31 个桩类，真实业务代码运行时由 native 解密 |
| 关键 native 库 | `libencrypt.so`（含 `Java_com_bangcle_comapiprotect_CheckCodeUtil_checkcode` / `decheckcode`）、`libEncryptorP.so`、`libnesec.so`、`librust_lib.so` |

**结论**：直接对当前版本 APK 做静态反编译（jadx）只能拿到壳，业务代码不可见。但 APK 中 `CheckCodeUtil.checkcode` 与第三方工具 ninecli 里重实现的 `crypto.ComputeCheckcode` 一一对应，即**请求校验码算法已被社区完整重实现**。

## 2. 云 API 全貌（静态恢复自 ninecli Go 二进制）

> **2026-08-07 增补**：本轮通过 GDB 断点 + 假服务器抓包，对认证签名与请求加密做了**端到端验证**，算法细节见 §5「认证与加密算法还原（已验证）」。

### 2.1 服务域名（5 个）

| 用途 | 默认地址 | CLI 覆盖参数 |
|---|---|---|
| Passport 认证 | `https://api-passport-bj.ninebot.com` | `--passport-base` |
| 业务登录（jhcx v6 北京） | `https://api-jhcx-v6-bj.ninebot.com` | `--biz-host` |
| 行程数据（CN CBU 网关） | `https://cn-cbu-gateway.ninebot.com` | `--travel-host` |
| 车辆控制（电动自行车） | `https://ebike.ninebot.com` | `--ebike-host` |
| 电机/其他 | `https://steeldust.ninebot.com` | `--motor-host` |

### 2.2 接口路径（反汇编级确认，2026-08-07 第二轮增补）

> 以下路径均为 capstone 对 `ninecli` 二进制逐指令反汇编确认：从
> `Business.Travel / TravelDetail / Vehicles` 函数内的 `lea rip-relative`
> 定位 rodata 字符串起点，并以 `mov esi, <长度>` 校验字符串长度完全吻合。

**Passport（api-passport-bj.ninebot.com）**
- `POST /v6/user/login` —— 密码登录（动态抓包验证）
- `POST /v6/user/phoneCodeLogin` —— 验证码登录
- `POST /v6/user/login/v4/code/phone` —— 发送短信验证码（请求体含 `checkcode` 字段）
- `POST /v3/user/refresh` —— 刷新 access_token
- `POST /v5/user` —— whoami / 校验 token

**行程（cn-cbu-gateway.ninebot.com，请求体/响应体加密）**
- `POST /app-api/travel/v6/travel-list` —— 按月行程列表
  - 证据：`Business.Travel` @0x6d3011 `lea rdi,[rip+0x21365a]` → rodata 0x8e6672，
    `esi=0x1f`(31)，字符串 `/app-api/travel/v6/travel-list` 恰为 31 字节；`r9d=6`（POST）
- `GET /app-api/travel/v6/travel-info` —— 单次行程详情
  - 证据：`Business.TravelDetail` @0x6d383a `lea rdi,[rip+0x212320]` → rodata 0x8e5b61，
    `esi=0x1e`(30)，字符串 `/app-api/travel/v6/travel-info` 恰为 30 字节；`r9d=5`（GET）
- MCP/本地 proxy 的 `GET /vehicles/{sn}/travel/{detail_id}` 是 **本地 REST 路由**，
  不是九号 API 路径（勿混淆）

**车辆 / 电池（cn-cbu-gateway 域）**
- `/vehicle/binding/my-vehicle` —— 车辆列表
  - 证据：`Business.Vehicles` @0x6d3f53 `lea rdi,[rip+0x20f944]` → rodata 0x8e389e
- `/v6/vehicle/battery-info` —— 电池信息（字符串池确认）

**控制（ebike.ninebot.com，本轮未细挖——用户明确不需要）**
- `POST /vehicles/{sn}/engine/start`、`POST /vehicles/{sn}/engine/stop`（字符串池确认）
- `open_buck`（开座桶）、`bell`（响铃）—— 控制命令存在但未展开逆向

### 2.3 请求头（二进制字符串恢复）

```
Platform-Ver / platform / platform_ver
Sys-Language / sys_language
Service-Time
need_decrypt          # 加密开关
Device-Id             # 设备 ID（config.json 中 device_id）
client_ver / Client-Ver
Request-Id
os_version
rn / rn-version / rn-module
Ninebot-Version / current_version
Business-Type
Login-Country / login_country
Authorization
User-Agent: okhttp/4.9.1
```

### 2.4 加密协议（"网易加密层"，ninecli `internal/crypto` 完整重实现）

```
crypto.ComputeCheckcode   ← 对应 APK libencrypt.so 的 Bangcle CheckCodeUtil.checkcode
crypto.GenKeyData         → KeyData{One, Two, Three, Four}（4 个密钥分量）
crypto.GenKReq            → key request（与服务器交换密钥）
crypto.BuildWrapper       → 请求包装
crypto.EncryptRequest / crypto.DecryptResponse   ← AES + PKCS7
crypto.DeriveKey / GenNonce
crypto.PassportCanonicalString / crypto.PassportSign  ← Passport 请求签名（ClientID/ClientKey）
crypto.AndroidB64
```

响应/请求密钥字段：`keyDataOne`、`keyDataTwo`、`keyDataThree`、`keyDataFour`、`need_decrypt`。

### 2.5 数据模型（GoReSym 从类型元数据恢复）

```go
// tokens.json（登录后保存）
type Tokens struct {
    UUID        string `json:"uuid"`
    Username    string `json:"username"`
    Phone       string `json:"phone"`
    Region      string `json:"region"`
    AreaCode    string `json:"areaCode"`
    AccessToken string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
    AccessTokenValidity string `json:"accessTokenValidity"`
    BusinessUID string `json:"business_uid,omitempty"`
    SavedAt     int64  `json:"saved_at"`
}

// config.json（设备伪装）
type Config struct {
    DeviceID  string `json:"device_id"`
    Region    string `json:"region"`
    AreaCode  string `json:"area_code"`
    OSVersion string `json:"os_version"`
    OSModel   string `json:"os_model"`
}

// 车辆缓存
type CachedVehicle struct {
    WNumber      string `json:"wnumber"`
    VehicleName  string `json:"vehicle_name"`
    DeviceName   string `json:"device_name"`
    BusinessLine string `json:"business_line"`
}
```

### 2.6 行程数据字段（二进制字符串 + hasscc/ninebot 集成交叉验证）

**月度行程列表响应**（解密后 JSON）：
```json
{
  "list": [
    {
      "travel_id": "...",
      "start_time": "...",
      "end_time": "...",
      "mileages": 12.5,          // 里程 km
      "duration": 3600,          // 时长 s
      "used_electricity": 8,     // 耗电 %
      "max_speed": 25.0          // 最高速度 km/h（字段名以实际返回为准）
    }
  ],
  "total_mileages": 123.4,
  "ec": "...",
  "used_electricity": 8
}
```

**行程详情响应**：含 `travel_details`，逐点轨迹/速度数据（起止时间 CST、时长秒数已确认）。

**CLI 输出格式串（证明 max 速度在服务端数据中）**：
```
%s  %d rides  %.1fkm  %.0fs  max %.1fkm/h  %.0f%% used     ← 按天分组行
  start    %s CST
  end      %s CST  (%.0fs)
```

**结论**：最高速度字段服务端直接下发（无需计算）；平均速度 = 里程 ÷ 时长（或对逐点速度取平均），两种方式均可由原始数据算出。

## 3. 可用工具链

**ninecli v0.1.7**（PyPI，MIT）—— 已在本机验证可运行：

```bash
ninecli login -u <手机号> -p <密码>      # 密码登录（Passport），保存 tokens.json
ninecli login-code -m <手机号> -c <code>  # 短信验证码登录
ninecli whoami                            # 验证 token
ninecli vehicles                          # 车辆列表（SN / wnumber）
ninecli travel <SN> --month 202607 --json # 按月行程列表（原始解密 JSON）
ninecli travel <SN> --detail <travel_id> --json  # 单次行程详情
ninecli serve                             # 本地明文 REST 代理 :18009（网页展示可直接对接）
```

## 4. 结论

1. 当前 APK 被梆梆全量加固，**纯静态反编译不可行**；
2. 但完整 API（域名、路径、请求头、网易加密层、字段）已通过 ninecli 二进制静态恢复，且 ninecli 已用 Go 完整重实现加密层（含 checkcode）；
3. 行程列表与详情的原始数据中**包含最高速度**，平均速度可由里程/时长计算；
4. 下一步只需登录一次（密码或短信验证码）即可全量拉取历史行程；
5. 风险提示：登录行为可能使手机端 App 会话失效（重新登录手机端即可恢复）；建议仅对本人账号操作，遵守九号服务条款，数据仅自用。

## 5. 认证与加密算法还原（2026-08-07 动态验证）

### 5.1 Passport 签名算法（已端到端验证）

登录请求头 `Sign` 的生成：

```python
import hashlib

CLIENT_KEY = "e177176a-3b3e-1513-e26e-d1123034cb66"   # 硬编码在二进制中

def passport_sign(url: str, params: dict) -> str:
    """params 至少包含: app_version, areaCode, clientKey, device, os,
    os_language, os_version, password, timestamp, url, username"""
    params = dict(params)
    params["clientKey"] = CLIENT_KEY
    params["url"] = url
    canonical = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
    return hashlib.sha256(canonical.encode()).hexdigest()
```

**验证**：GDB 在 `crypto/sha256.Sum256` 断点抓到的 canonical 字符串，SHA256 结果与
假服务器实际收到的请求头 `Sign` **完全一致**。

验证用完整 canonical 样例：
```
app_version=610063322&areaCode=86&clientKey=e177176a-3b3e-1513-e26e-d1123034cb66&device=ANDROID&os=Android&os_language=zh-hans-cn&os_version=13&password=endtoendpw1&timestamp=1786095783403&url=/v6/user/login&username=e2etest
```

### 5.2 请求加密（business API，网易加密层）——抓包确认

实际发出的 business 请求体（`POST /user/user/login`，`api-jhcx-v6-bj.ninebot.com`）：

```json
{
  "d": "<base64: AES-128-CBC 加密的业务数据>",
  "h": "<32位hex: MD5>",
  "k": "<base64: RSA-1024 加密的 AES 密钥>",
  "p": "101",
  "t": "0"
}
```

流程（`EncryptRequest` 反汇编确认，2026-08-07 第三轮细化）：
1. `GenKReq()` 生成 **16 字节随机 AES 密钥**（94 个可打印 ASCII 字符集，`!"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~`）
2. `GenKeyData()` 生成 4 个随机密钥分量 `KeyData{One,Two,Three,Four}`（`randHex(11), randHex(11), randHex(10), randFromCharset(8, 69字符集)`）—— 分量放进明文 wrapper 传给服务器，**服务器用它派生响应加密密钥**
3. `crypto/rsa.EncryptPKCS1v15` 用内置 RSA-1024 公钥加密 AES 密钥 → `k`
4. `crypto/aes.NewCipher` + `crypto/cipher.NewCBCEncrypter`（**IV = 16 个零字节**，反汇编确认 0x6ccbcc 分配清零缓冲区后直接作 IV）加密业务数据 → `d`
5. `crypto/md5.Sum`（0x5d1780，初始常量 0xefcdab8967452301/0x1032547698badcfe 实锤）对**明文 wrapper** 求 MD5 → `h`
6. 组装 `{"d","h","k","p":"101","t":"0"}`（D/H/K/P/T 结构体 json tag 从类型元数据 @0x3f53dd 恢复）

内置 RSA-1024 公钥（二进制中 PEM 硬编码）：
```
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6maFY3dEhgav1147RW2gVWzCv
agkiRySnCDRSTM67YhHvLcrUSMnngxJl0A2liFLJydpn65E58oh0Phtu+t4Kkkfe
GIHsr931wRMRtkila4F/RF3U5pqSt42k/10U087QEhGMGvdOzF/5ziGXJod6ovBx
yk6pJlzNhxLTVJSzkQIDAQAB
-----END PUBLIC KEY-----
```

### 5.3 响应解密（`DecryptResponse` 反汇编确认）

响应格式：`{"r": "<base64>"}`，`r` base64 解码后为 AES-128-CBC 密文。
**响应解密密钥 = `DeriveKey(KeyDataOne, KeyDataTwo, KeyDataThree, KeyDataFour)`**（与请求的
GenKReq 随机密钥无关，是第二把独立密钥）；`AESDecrypt`（同样 IV=0 + PKCS7 unpad）后得到业务 JSON。
完整公式见 §6.1。

## 6. 网易加密层完整还原（2026-08-07 第三轮：公式级，unicorn 动态验证）

> 本轮把 DeriveKey / AndroidB64 / BuildWrapper / EncryptRequest / DecryptResponse / GenKReq /
> GenKeyData **全部抠到公式级**，并用 unicorn 执行二进制原始机器码交叉验证。
> 纯 Python 实现见 `ninebot_crypto.py`（自检 round-trip 全部通过）。

### 6.1 DeriveKey 公式（已验证 ✅）

`DeriveKey(A, B, C, D []byte) [16]byte`，@0x6c99e0-0x6c9b80。Go 内部 ABI 参数：
`rax=A_ptr rbx=A_len rdi=B_ptr rsi=B_len r9=C_ptr r10=C_len`，D 走栈参数 `[入口rsp+8]/[+16]`。

```python
def rol8acc(s):                     # 每个输入的 ROL8 累加
    v = 0
    for b in s: v = rol32(v, 8) ^ b
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

**验证**：`verify_derivekey.py` 用 unicorn 直接执行二进制里 DeriveKey 的机器码
（hook 唯一外部调用 0x478860 堆分配），11 组测试向量（空输入/单字节/二进制随机）
与 Python 公式输出**完全一致，ALL PASS**。已知向量：
`derive_key(b"abcdefghijklm", b"0123456789ab", b"XYZ", b"ninebot!") = 82ffe6a8cbb9a4ffdbf791a74e37176e`

### 6.2 AndroidB64（已验证 ✅）

@0x6c95a0，模拟 Android `Base64.DEFAULT`：标准 base64 编码 + **每 76 字符插 `\n` + 非空时末尾恒有 `\n`**。
**验证**：`verify_androidb64.py` unicorn 执行机器码，9 组长度（1/5/56/57/58/113/114/115 字节）全部一致。

### 6.3 明文 wrapper（BuildWrapper @0x6cc4c0）

拼接顺序（lea 序列逐条确认，`h = md5(此明文)`，字节必须精确）：
```json
{\n
\t"data" : "<jsonEscape(AndroidB64(业务JSON))>",\n
\t"keyDataFour" : "<kd4>",\n
\t"keyDataOne" : "<kd1>",\n
\t"keyDataThree" : "<kd3>",\n
\t"keyDataTwo" : "<kd2>",\n
\t"platform" : 10,\n
\t"timeStamp" : <Unix毫秒>\n}\n
```
- `jsonEscapeString`（@0x6cc7a0）：标准 JSON 转义（`"`→`\"`、`\`→`\\`、`\n`→`\n`、`\r`、`\t`），首尾加引号
- data 字段必须转义：AndroidB64 输出含 `\n`
- platform 值由调用方传入（默认 10 = Android，与请求头 `Platform: Android` 一致）

### 6.4 密钥材料（GenKReq / GenKeyData）

- `GenKReq()` @0x6ca880：16 字节，字符集 = 94 个可打印 ASCII → **请求 AES 密钥**
- `GenKeyData()` @0x6cab20：`(randHex(11), randHex(11), randHex(10), randFromCharset(8, 69字符集))` → **4 个 keyData 分量**（响应密钥派生用）
- `randFromCharset` 用**拒绝采样**（`rand < len(charset)` 才取用，非取模）

### 6.5 请求 / 响应密钥体系（两把独立密钥）

| 方向 | 密钥 | 传递方式 |
|---|---|---|
| 请求加密 d | GenKReq 16 字节随机 | `k` = RSA-1024(AES key) b64 |
| 响应加密 | DeriveKey(kd1,kd2,kd3,kd4) | 服务器从明文 wrapper 的 keyDataOne..Four 取分量 |

### 6.6 验证工具（workspace 内）

| 文件 | 作用 |
|---|---|
| `ninebot_crypto.py` | 纯 Python 完整实现（不依赖 ninecli），含自检 |
| `verify_derivekey.py` | unicorn 执行二进制 DeriveKey，对照 Python 公式 |
| `verify_androidb64.py` | unicorn 执行二进制 AndroidB64，对照行为 |
| `verify_buildwrapper.py` | unicorn 执行二进制 BuildWrapper（runtime 写屏障未完全模拟，格式以反汇编为准） |

### 5.4 完整请求头（抓包确认）

```
User-Agent: okhttp/4.9.1
Business-Type: 0
Client-Ver: 610063322
Content-Type: text/html;charset=UTF-8
Debug: 0
Device-Id: <16字节随机hex>
Language: zh
Login-Country: CN
Need_decrypt: 1
Ninebot-Version: 2
Platform: Android
Platform-Ver: 13
Regionx: bj
Request-Id: <32位hex>
Service-Time: <毫秒时间戳>
Sys-Language: zh-hans-cn
```

### 5.5 接口路径（动态抓包确认）

- `POST /v6/user/login` —— Passport 密码登录（api-passport-bj）
- `POST /user/user/login` —— business 登录（api-jhcx-v6-bj，换 business token）

### 5.6 审计结论

详见 `docs/security-audit.md`：未发现恶意代码；全部网络端点仅九号官方 5 域名；
无命令执行/动态加载/隐藏载荷；凭据仅发往 Passport 端点。

## 7. 第五轮增补（2026-08-07 动态抓包级确认，纯 Python 客户端交付）

> 本轮用 GDB 断点（ComputeCheckcode/AESEncrypt/MD5/EncryptPKCS1v15）+ 假服务器抓包，
> 把所有请求的内层明文、wrapper、请求头**逐字节抓出**，并交付
> `ninebot_api.py`（纯 Python 客户端，零二进制依赖）+ 改造 `fetch_trips.py`。

### 7.1 RSA 密钥纠正（重要）

- 二进制有**两把 RSA-1024 公钥**：
  - **N1 = `d3de6d1c...`**（DER SPKI @VA 0xc2e020，140B，被 crypto.init.0 @0x6c9b92
    解析并缓存到 0xc87c00；EncryptRequest @0x6ca193 取用 → rsa.EncryptPKCS1v15 @0x5cc120）。
    **这是真实服务器认的密钥**（GDB 抓 EncryptPKCS1v15 实参确认 N=rsa_n_1.bin）。
  - **N2 = `ba99a158...`**（PEM 字符串 @VA 0xc2fae5，266B）——**死数据**，全文搜索
    无任何 (ptr,len) 字符串头 / RIP 引用指向它（旧版遗留）。
- 之前文档与 ninebot_crypto.py 误用 N2 的 PEM；已改为 N1。
- 验证：用 N1 加密抓包的 AES key 无法与 wire.k 逐字节比对（PKCS1v15 随机填充），
  但反汇编 + GDB 实参 + ninecli 可用性构成完整证据链。

### 7.2 路径/方法纠正（动态抓包为准）

| 接口 | 路径（实测） | 方法（实测） |
|---|---|---|
| 行程列表 | `/app-api/travel/v6/travel-list2`（31B，注意带 `2`！） | **POST** |
| 行程详情 | `/app-api/travel/v6/travel-info`（30B） | **POST**（非 GET） |
| 车辆列表 | `/vehicle/binding/my-vehicle`（主机为 **ebike.ninebot.com**，非 cbu-gateway） | POST |
| business 登录 | `/user/user/login`（api-jhcx-v6-bj） | POST |

### 7.3 内层 JSON：struct 字段顺序（非 map 排序）

GDB 抓包（446B/383B/485B 三例）证实内层是 **Go struct 序列化**，字段顺序固定：

```
公共（11 字段）: sys_language, client_ver, device_id, regionx, language, ostype,
                 lang, platform_ver, platform, login_country
business login : + access_token, uuid, token, refresh_token, region, serviceTime, nonce
vehicles       : + access_token, uid, vehicle_type("65"), serviceTime, nonce
travel-list    : + access_token, uid, wnumber, rnVersion("743"), vehicle_type("112"),
                 month, page("1"), current_version, serviceTime, nonce
travel-info    : + access_token, uid, wnumber, rnVersion, vehicle_type, travel_id,
                 current_version, serviceTime, nonce
```

- `checkcode` = MD5(无 checkcode 的内层紧凑 JSON).upper()，追加为最后字段。
- Go `encoding/json` 输出：紧凑、`<>&`→`\u003c...`、非 ASCII 原样（Python 已对齐）。

### 7.4 wrapper 与响应格式

- business 域 wrapper：**platform=2、timeStamp=Unix 秒**（非 10/毫秒），data 为 AndroidB64。
- 响应 wire 层：**`{"r": b64}`**；业务 `code/data/message` 在**解密后的内层**。
- Business 方法返回内层 `data` 字段（剥离 code/message）。
- 请求头：business login 用 Business-Type:0（无 Access_token）；vehicles/travel 用
  Business-Type:2 + `Access_token` + `Accept: application/json` + `Rn-Module: Track` +
  `Rn-Ver: 743` + `Rn-Version: 0`。
- vehicles 的 business_line 判定：`ebike`→ebike 主机、`motor`→steeldust（travel 命令
  只接受这两种，否则 "unknown business line"）。

### 7.5 交付物

| 文件 | 说明 |
|---|---|
| `ninebot_api.py` | 纯 Python 客户端：passport 登录/刷新、business 登录、vehicles、travel-list/info；`--self-test` 无账号自测 |
| `ninebot_crypto.py` | 加密层（已换 N1 公钥、加 gen_nonce/build_inner、business 域默认 platform=2/秒） |
| `fetch_trips.py` | 已改为调用 ninebot_api，零 ninecli 依赖 |
| `gdb_capture_all.gdb` | 新一代抓包脚本（计数器区分多次请求） |
| `disasm_func4.py` | lea+长度配对精确切串工具 |

### 7.6 用户使用

```bash
python3 ninebot_api.py --self-test                 # 无账号自测
python3 ninebot_api.py login -u <手机号> -p <密码>  # 登录（存 tokens.json）
python3 ninebot_api.py vehicles                    # 车辆列表
python3 fetch_trips.py                             # 全量抓行程
```


---

## 7. 第七轮补充（2026-08-07）：假服务器打通 + 响应链路修正

### 响应解密链路（修正）
二进制 `DecryptResponse` @0x6ca300 解 `{"r": b64}` 后，**明文是 wrapper JSON**：
```json
{"data": "<AndroidB64(业务JSON)>", "platform": 2, "timeStamp": <秒>}
```
客户端再解析 wrapper 取 `data` → AndroidB64 解码 → 业务 JSON。
（错误串 `decrypt failed: missing 'data' field in wrapper` 证实。）
`ninebot_crypto.unwrap_response()` 实现该层。

### travel-list 路径实锤
`POST /app-api/travel/v6/travel-list2`（带 2，fake 服务器记录真实请求路径）。

### 行程列表真实字段（printTravelGroups.func1 @0x796ae0 反汇编）
| 字段 | 类型 | 说明 |
|---|---|---|
| `travel_id` | string | id |
| `end_time_format` | string | `"2026-08-01 08:30:00"`，二进制取 `[11:16]` 显示 HH:MM |
| `mileages` | string | 里程 km（ParseFloat） |
| `duration` | 数字 | 时长 s |
| `speed` | string | **最高速 km/h**（ParseFloat） |
| `used_electricity` | string | 耗电 %（ParseFloat） |

汇总行：mileages 总和 / duration 总和 / speed 最大 / used_electricity 总和。

### 请求参数实测（GDB 抓包）
- vehicles：`vehicle_type="64"`
- travel：`rnVersion="743"`、`vehicle_type="112"`（0x8d7b06 `743112` 硬编码）、`current_version=610063322`

### 工具
- `fake_server4.py`：GDB 抓 wrapper → 提取 kd1..4 → Python 复算 DeriveKey → 构造合法加密响应。二进制全链路跑通输出：
  `08/01  1 rides  12.5km  1800s  max 45.2km/h  8% used`
