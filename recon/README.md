# recon/ — 逆向分析与取证脚本

分析对象：**ninecli v0.1.7**（PyPI，Go 语言的九号云 API 客户端）的 Linux x86_64 二进制。
本目录脚本是 `docs/` 各报告结论的取证过程，按工作轮次演进；最终结论以 `docs/reverse-engineering-full-report.md` 为准。

## 分析对象与本地大文件（不随仓库分发）

### 分析对象：ninecli 0.1.7 二进制（对照验证请认准校验和）

本项目全部分析针对 **ninecli v0.1.7** 的 `manylinux_2_17_x86_64` wheel（MIT 许可），
获取方式（任选其一）：

```bash
pip download ninecli==0.1.7 --no-deps --platform manylinux_2_17_x86_64 --only-binary :all:
# 或 pip install ninecli==0.1.7，二进制在 site-packages/ninecli/bin/ninecli
```

校验和（本仓库所有 docs 中的地址/偏移均基于此文件）：

```
ninecli-0.1.7-py3-none-manylinux_2_17_x86_64.whl
  SHA256 = ff3941b81d60e4bba60e9477900e63a9ebd2b02e74cb4b8138f3cfe1d94a81cc
解压后 ninecli/bin/ninecli（8.9MB 静态 ELF，Go 1.x）
  SHA256 = faaa5b841427e8d3018321e6ae7db9b26921600b2ef4c8bafd48640edaac0126
```

若 PyPI 下架，本仓库 Releases 页附有原样 wheel 存档。注意 PyPI 还有 macOS/Windows/aarch64 等
其他平台的 wheel，**各平台二进制不同，地址偏移不可混用**；本文档结论只适用于 Linux x86_64 版。

### 其他本地大文件

- 九号官方 APK（`ninebot_xiaomi.bin`，258MB，梆梆加固）：小米应用商店直链，见九号官网下载页。
- 再生成两个大产物：
  - `gore_out.json`（GoReSym 符号表，82MB）：`./GoReSym -t -d -p <ninecli二进制> > gore_out.json`
  - `dis.txt`（全量反汇编，29MB）：`objdump -d <ninecli二进制> > dis.txt`

## 地址换算

`.text`  VA 0x401000 ↔ 文件偏移 0x1000；`.rodata` VA 0x7ee000 ↔ 文件偏移 0x3ee000。

## 脚本清单

### 静态反汇编工具

| 脚本 | 说明 |
|---|---|
| `disasm_func.py` ~ `disasm_func4.py` | 函数级反汇编 + 字符串交叉引用定位（strings/capstone），第 4 版为终版；`BIN` 常量指向本地 ninecli 二进制 |
| `dump_crypto_funcs.py` → `dump_crypto.txt` | 批量提取 crypto/api 包 18 个函数的反汇编（`crypto-vs-disasm.md` 的对照底稿） |

### 公式验证（unicorn 执行二进制原始机器码，交叉验证 Python 实现）

| 脚本 | 说明 |
|---|---|
| `verify_derivekey.py` | DeriveKey 公式，11 组测试向量 ALL PASS |
| `verify_androidb64.py` | AndroidB64（base64 + 每 76 字符插 \n + 末尾 \n），9 组 ALL PASS |
| `verify_buildwrapper.py` | wrapper 明文构造（字段序/转义规则），逐字节比对 |

### 假服务器（记录真实请求 / 构造加密响应）

| 脚本 | 说明 |
|---|---|
| `fake_passport.py` / `fake_passport2.py` | Passport 端点假服务器（第二轮，抓登录请求全貌、验证签名算法） |
| `fake_server3.py` | 第三轮迭代 |
| `fake_server4.py` | 终版：收加密请求 → 读 GDB 抓到的 kd1..4 → Python 复算 DeriveKey → 回合法加密响应，完整跑通 login→refresh→vehicles→travel-list2 |

注意：fake_server4 依赖 GDB 抓密钥材料，纯 Python 客户端配合假服务器需 RSA 私钥或真服务器。

### GDB 断点取证脚本

配合 `gdb -x <script> --args ./ninecli ...` 使用，在加密/哈希入口断点抓寄存器与内存：

- 终版（第五~七轮）：`gdb_capture_all.gdb`（AES 入口 0x6ccac0 抓 wrapper 明文 / MD5 入口抓 checkcode 输入）、`gdb_buildinner.gdb`（内层 JSON 构造）、`gdb_encrypt_out.gdb`、`gdb_pt_slots.gdb`、`gdb_travel_plain.gdb`
- 早期迭代（第二~四轮，结论已固化进 docs）：`gdb_wrapper_cmds.gdb`、`gdb_checkcode_cmds.gdb`、`gdb_rsa_*.gdb`、`gdb_all*.gdb`、`gdb_final_cmds.gdb`
- `gdb_dump_wrapper.py`：GDB 脚本内调用的内存 dump 辅助

## 证据链速览

1. GoReSym 恢复 2338 个用户函数符号 → 定位 `internal/crypto` 与 api 包。
2. `disasm_func*` 交叉引用定位接口路径与常量（`travel-list2`、`'743112'`、两把 RSA 公钥等）。
3. unicorn（`verify_*`）证明 Python 公式与二进制机器码等价。
4. GDB 断点抓真实报文 → `ninebot_api.py` 的构造函数逐字节复现。
5. `fake_server4.py` 闭环验证响应解密链路。
