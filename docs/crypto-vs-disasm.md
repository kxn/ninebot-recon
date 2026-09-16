# ninebot_crypto.py vs ninecli 二进制反编译 —— 逐句对照报告

> 对照日期：2026-08-07（第六轮）
> 对照对象：`ninebot_crypto.py`（纯 Python 实现）vs `ninecli_wheel/ninecli/bin/ninecli`
> 反编译材料：`dis.txt`（objdump 全量反汇编，29MB）、`gore_out.json`（GoReSym 符号表）、GDB 动态抓包
> 方法：capstone/objdump 反汇编逐指令核对 + GDB 断点抓寄存器/内存 + unicorn 动态执行（前几轮）

---

## 结论速览

| 函数 | 状态 | 依据 |
|---|---|---|
| `derive_key` | ✅ 一致 | 反汇编逐指令 + unicorn 11 组 PASS |
| `android_b64` | ✅ 一致 | 反汇编 + unicorn 9 组 PASS |
| `gen_kreq` | ✅ 一致 | 字符集/拒绝采样逐字节核对 |
| `gen_nonce` | ✅ 一致 | 大小写规则逐指令核对 |
| `gen_key_data` | ✅ 一致 | 长度/字符集逐字节核对 |
| `rand_hex` / `rand_charset` | ✅ 一致 | 字符集 @VA + 拒绝采样边界 |
| `compute_checkcode` | ✅ 一致 | GDB 抓小写 hex → ToUpper |
| `build_wrapper` | ✅ 一致 | 全部 11 个字面量逐字节 + 字段序 |
| `_json_escape` | ✅ 一致 | 5 个转义分支逐指令 |
| `_pkcs7_pad/unpad` | ✅ 一致 | 逐指令（pad 1..16、逐字节校验） |
| `_aes_cbc_encrypt/decrypt` | ✅ 一致 | NewCipher→PKCS7→CBC→**内部 b64** |
| `encrypt_request` | ✅ 一致 | GDB 抓 D/H/K/P/T 实锤 |
| `decrypt_response` | ✅ 一致 | b64→DeriveKey→AESDecrypt |
| `build_inner` / `_go_json_dumps` | ⚠️ **有差异** | 见 §4：HTML escape 多余 |
| `PassportSign` 等 | ✅ 一致 | 第二轮端到端验证（docs/api-recon.md） |

---

## 1. 加密层核心（逐指令级）

### 1.1 DeriveKey @0x6c99e0-0x6c9b80 — 一致
- 4 个输入各自 ROL8 累加循环（`rol $0x8` + `xor`），与 `_rol8acc` 逐指令一致
- `x=A^C, y=B^D`；`fx=rol(x,8)^x^rol(x,24)`；`gy=rol(y,8)^y^rol(y,24)`（0x6c9a7f-0x6c9a9b）
- `a'=A^gy, b'=B^fx, c'=C^gy, d'=D^fx`（0x6c9a8c-0x6c9a9f）
- out3/out2/out1/out0 的 and/or/xor/not 序列（0x6c9aa1-0x6c9acd）与 Python 公式一一对应
- 内存写入：out0@0、out1@4、out2@8、out3@0xc（0x6c9ae9-0x6c9b04）= `struct.pack("<IIII")` 小端序
- 另有 unicorn 动态执行二进制机器码 11 组测试向量 ALL PASS

### 1.2 AndroidB64 @0x6c95a0-0x6c9840 — 一致
- `0x4edce0` = base64.StdEncoding.EncodeToString（全局 0xc87c50）
- 每 76 字符插 `\n`（0x6c962e `lea 0x4c(%rcx),%rdi` = 76 边界），非空末尾恒 `\n`（0x6c9611/0x6c9609 路径）
- 空输入返回空串（0x6c95fc-0x6c9608）
- unicorn 9 组 ALL PASS

### 1.3 GenKReq @0x6ca880-0x6ca9e0 — 一致
- 16 次循环（`cmp $0x10,%rcx`）
- 字符集 @VA 0x8f9864 = `!"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~`（94 个可打印 ASCII）——与 `CHARSET_KREQ` 逐字节一致
- 拒绝采样：`movq $0x5e,0x30(%rsp)`（bound=94），`cmp $0x5e,%rdx; jb` 循环
- 随机源 0x5a9520 = math/rand/v2（0xc88300 全局 rand 实例）

### 1.4 GenNonce @0x6ca9e0-0x6cab20 — 一致
- 0x5a93e0 = crypto/rand.Read（16 字节）
- **首字节**两个 hex 字符：`cmp $0xa; jae +0x57`（0x57='a'-10 → 小写 a-f）
- **其余 15 字节**：`+0x37`（0x37='A'-10 → 大写 A-F）
- = Python `h[0:2].lower() + h[2:].upper()` ✓

### 1.5 GenKeyData @0x6cab20-0x6cac40 — 一致
- 3 次 randHex：11、11、10（eax 立即数）
- 1 次 randFromCharset：8 字符、字符集 @VA 0x8f6f46 = `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789;-_.,+/`（69 字符）——与 `CHARSET_KEYDATA4` 逐字节一致

### 1.6 randHex @0x6cad40-0x6caea0 / randFromCharset @0x6caea0-0x6cb020 — 一致
- randHex：字符集 @0x8dc865 = `0123456789abcdef`（小写 hex），拒绝采样 bound=16（`cmp $0x10,%rdx; jb`）
- randFromCharset：`movzbl (%rbx,%rdx,1),%edi` 按索引取字符，拒绝采样 `cmp %rdx,%rcx; ja`（rcx=charset len）
- 两者都是 math/rand/v2 IntN 拒绝采样 = Python `secrets.randbelow`

---

## 2. Wrapper / 内层构造

### 2.1 BuildWrapper @0x6cc4c0-0x6cc7a0 — 一致
逐字节确认的拼接字面量（0x4f6220 = bytes.Buffer append）：

| VA | 字节 | 说明 |
|---|---|---|
| 0x8d79a2 | `{\n` | 开头 |
| 0x8d9e2d | `\t"data" : ` | data 键 |
| （AndroidB64 → jsonEscapeString） | | data 值 |
| 0x8d79a4 | `,\n` | 分隔 |
| 0x8de1d1 | `\t"keyDataFour" : "` | kd4 键 |
| kd4 | | 第 4 分量 |
| 0x8d7b4b | `",\n` | 分隔 |
| 0x8dd7ec | `\t"keyDataOne" : "` | kd1 键 |
| kd1 | | |
| 0x8d7b4b | `",\n` | |
| 0x8deb4c | `\t"keyDataThree" : "` | kd3 键 |
| kd3 | | |
| 0x8d7b4b | `",\n` | |
| 0x8dd7fd | `\t"keyDataTwo" : "` | kd2 键 |
| kd2 | | |
| 0x8d7b4b | `",\n` | |
| 0x8dbeed | `\t"platform" : ` | platform（0x48df60=十进制） |
| 0x8d79a4 | `,\n` | |
| 0x8dc544 | `\t"timeStamp" : ` | timeStamp（十进制） |
| 0x8d7b4e | `\n}\n` | 结尾 |

字段顺序：data → keyDataFour → keyDataOne → keyDataThree → keyDataTwo → platform → timeStamp，与 Python `build_wrapper` 完全一致。
- platform 来自入参（业务域=2，PostWithExtras 调用链确认）
- timeStamp 来自入参：0x6cf423 `movabs $0xfffffff1886e0900`（=-62135596800 秒偏移）+ time.Now() → **Unix 秒**
- 注意：**毫秒只在** CommonParams 内层 serviceTime 用（0x6cf2a4 `imul $0x3e8`）

### 2.2 jsonEscapeString @0x6cc7a0-0x6cc960 — 一致
| 字符 | 输出 | 分支 |
|---|---|---|
| 0x09 \t | `\t` | 0x6cc851 |
| 0x0a \n | `\n` | 0x6cc839 |
| 0x0d \r | `\r` | 0x6cc8ca |
| 0x22 " | `\"` | 0x6cc8aa |
| 0x5c \ | `\\` | 0x6cc88c |
| 其他（含非 ASCII） | 原样 | 0x6cc87b |

开头/结尾各补 `"`（0x6cc7d3/0x6cc8ef）。与 `_json_escape` 一致。

### 2.3 ComputeCheckcode @0x6cac40-0x6cad40 — 一致
- 0x5d1780 = MD5（16 字节）
- hex 编码用 0x8dc865 字符集（小写）→ GDB 抓到 `369d37ece0c78100f92680cb7bee9868` 小写
- 0x4f3dc0 = strings.ToUpper → 大写
- = Python `hashlib.md5(...).hexdigest().upper()` ✓

### 2.4 BuildInner @0x6cece0-0x6cf0e0 — 一致
- EncodeOrderedJSON(有序 map) → 紧凑 JSON 主体
- ComputeCheckcode(主体) → 大写 hex
- 拼接：`主体去掉结尾 }` + `,"checkcode":"` + cc + `"}`（0x6cf00c-0x6cf040，0x8dbca1='`,"checkcode":"`' len 14）
- 与 Python 两次 dumps 结果一致（checkcode 恒在最后）

---

## 3. AES / RSA / 请求封装

### 3.1 PKCS7Unpad @0x6cc960-0x6ccac0 — 一致
- 空 / 非 16 倍数 → 报错（`pkcs7: invalid data length`）
- pad = 末字节，范围 1..16，逐字节校验，非法 → `pkcs7: inconsistent padding` / `pkcs7: invalid pad byte`
- 与 `_pkcs7_unpad` 一致

### 3.2 AESEncrypt @0x6ccac0-0x6ccce0 — 一致
- 0x5cf9e0 = aes.NewCipher → BlockSize()=16（0x6ccb13 `mov 0x18(%rax),%rcx` 间接调用）
- PKCS7 pad：`cqto; idiv %rcx; sub %rdx,%rcx` = `block - len%block`，`mov %dl,(%rax,%rcx,1)` 填充
- 0x58d060 = cipher.NewCBCEncrypter（IV 参数经 0x48df60? 需确认 IV=0，GDB 已确认）
- CryptBlocks 间接调用（0x6ccc0a `call *0x20(%rax)`）
- **0x6ccc20 call 0x4edce0 = 内部直接 b64 输出**（返回 b64 字符串）
- Python `_aes_cbc_encrypt` 输出密文 bytes，b64 在 `encrypt_request` 里做 → **结果一致**（位置不同）

### 3.3 EncryptRequest @0x6ca000-0x6ca300 — 一致（GDB 实锤）
GDB 抓返回结构体（0x6ca260，rsp+0x160 起 0x50 字节）：
```
D = 'QNREyiUkEozAKXrOWIfFAtdQk32Dl0kGbXz6xSqnieDD...'  ← b64(AES-CBC(wrapper))
H = 'd8b579b27fecf221d7d7e3d63481b5f4'                  ← md5hex(wrapper) 小写
K = 'WGnwA/FFc1MW01c3vxRkhee/42rUYrjwV38/PVRIBxR7gR30...' ← b64(RSA-1024(AESkey))
P = '101'
T = '0'
```
- MD5 输入 = BuildWrapper 明文（0x6ca0ea call 0x5d1780，rax=wrapper）
- hex 编码小写（0x8dc865 字符集）
- RSA = 0x5cc120 (EncryptPKCS1v15)，pubkey 全局 0xc87c00（= init.0 解析的 N1）
- P/T 来自 0x998070 静态模板（80 字节 memmove 0x47eb1a 复制到返回结构体），模板内 P='101' T='0'
- AES key 16 字节（GenKReq 输出）经 GDB 在 0x6ccac0 断点确认

### 3.4 DecryptResponse @0x6ca300-0x6ca880 — 一致
- 0x4ee2e0 = base64 decode（`decrypt failed: base64 r:` 错误路径）
- DeriveKey(kd1,kd2,kd3,kd4)（0x6ca4ad call 0x6c99e0，参数顺序 rax/rbx=kd1, rdi/rsi=kd2, r9/r10=kd3, 栈=kd4）
- AESDecrypt（0x6ca4d3 call 0x6ccce0）→ PKCS7Unpad
- 与 Python `decrypt_response` 完全一致

---

## 4. ⚠️ 发现的差异（需修复）

### 4.1 `_go_json_dumps` 多了 HTML escape 和 U+2028/2029 转义
- Python 现有实现：
  ```python
  s = json.dumps(d, sort_keys=False, separators=(",", ":"), ensure_ascii=False)
  s = s.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
  s = s.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
  ```
- 二进制 `writeJSONValue` @0x6cc0a0 字符串分支（0x6cc362-0x6cc485）**只转义 5 个字符**（`\n \t \r " \`），`<>&`、U+2028/2029、其他控制字符、非 ASCII **全部原样输出**（utf8.DecodeRune 后 append rune）
- key 处理（EncodeOrderedJSON 0x6cbf42-0x6cbf6a）也是直接 append，不转义
- **影响**：当前业务参数（手机号/token/sn/时间戳）不含 `<>&`/U+2028/2029/控制字符，实测输出一致；但严格逐字对照下 Python 实现与二进制语义不同
- **修复**：改为自定义编码器精确模拟（见 `ninebot_crypto.py` 新 `_go_json_dumps`）
- 另外 Python `json.dumps` 对 `\b \f` 等控制字符会转义，二进制原样输出 → 一并修复

### 4.2 float 格式差异（理论性）
- 二进制 float：0x48a9a0（strconv.AppendFloat 'f' 格式）
- Python：repr(float)
- 业务请求参数无 float 字段，无实际影响，仅记录

### 4.3 `json.dumps` 依赖 Python 的 dict 插入顺序
- 二进制是显式有序 map；Python 依赖 dict 有序（3.7+ 保证）→ 调用方按抓包顺序构造即可，已在 `ninebot_api.py` 遵守

---

## 5. 动态验证记录（本轮 GDB）

| 断点 | 抓取内容 | 结果 |
|---|---|---|
| 0x6ca1e5 | b64(RSA) 返回 K | `WGnwA/FFc1MW01c3...` len 172 |
| 0x6ca250 | K 写入前寄存器 | rax/rbx 未被 0x47eb1a 破坏 |
| 0x6ca260 | EncryptRequest 返回结构体 | D/H/K/P/T 全部正确 |
| 0x6cace5 | ComputeCheckcode 的 hex | 小写 `369d37ec...` → ToUpper |
| 0x6ca1e5/0x6ca213 | P/T 槽位 | 0x47eb1a memmove 后填 '101'/'0' |

---

## 6. 结论

**17/18 个函数逐句一致**（含 DeriveKey/AndroidB64 的 unicorn 机器码级验证）。
唯一需要改的是 `_go_json_dumps` 的转义语义（4.1），已修复并重新验证抓包复现。
