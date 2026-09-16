# 九号出行 · 历史行程数据导出 + 速度可视化

把九号出行 App 隐藏的**最高速度 / 平均速度**算出来，用网页看板展示。

## 原理

当前 APK（`cn.ninebot.ninebot` v6.x）被**梆梆全量加固**，直接 jadx 反编译拿不到业务代码。
本仓库以第三方 Go 客户端 **ninecli**（PyPI/MIT）的二进制为分析对象，
把九号云 API（Passport 认证 + 网易加密层 + 5 个业务域名）**公式级还原为纯 Python 实现**
（`ninebot_crypto.py` + `ninebot_api.py`），全部算法经 unicorn 执行二进制机器码与
GDB 抓包逐字节验证；checkcode 校验码算法与 APK 里 `libencrypt.so` 的
`CheckCodeUtil.checkcode` 对应。过程与证据见 `docs/`，工作日志见 `MEMORY.md`。

## 快速开始

```bash
# 1. 登录（密码登录；tokens 保存到 ~/.config/ninebot/tokens.json）
python3 ninebot_api.py login -u <手机号> -p <密码>

# 2. 全量抓取历史行程（默认 2022-01 至今；加 --no-detail 可跳过详情只抓列表）
python3 fetch_trips.py

# 3. 打开看板
#    在浏览器打开 index.html（需与 trips.json 同目录；可直接双击，
#    或 python3 -m http.server 8000 后访问 http://localhost:8000）
```

不依赖任何第三方二进制；抓取前可先跑 `python3 ninebot_api.py --self-test` 做无账号全链路自测。

抓取脚本输出：
- `trips.json` —— 看板数据（已算好 max/avg 速度）
- `trips.csv` —— 表格
- `cache/` —— 每月/每条行程的原始解密 JSON（断点续传，重复跑不重复请求）

## 常用参数

```bash
python3 fetch_trips.py --from 202401 --to 202412   # 指定月份区间
python3 fetch_trips.py --sn <车辆SN>                # 只抓某辆车
python3 fetch_trips.py --no-cache                  # 忽略缓存重新请求
```

## 网页看板功能

- 总览卡片：次数 / 总里程 / 总时长 / 历史最高速 / 整体与单次最佳平均速度
- 月度里程柱状图（Canvas，无外部依赖）
- 行程表：按时间/里程/时长/最高速/平均速/耗电排序、筛选（车辆、月份、关键字）
- 单条展开：Leaflet 轨迹地图（离线自动降级为 Canvas 平面图）+ 逐点速度曲线
- 当前 `trips.json` 为 **120 条示例数据**（带 demo 标记，页面顶部会提示），跑一次抓取脚本即被真实数据覆盖

## 目录

```
ninebot_crypto.py   加密层纯 Python 实现（AES-CBC/RSA/DeriveKey/checkcode/AndroidB64）
ninebot_api.py      云 API 纯 Python 客户端（登录/车辆/行程，--self-test 自测）
fetch_trips.py      批量抓取脚本（自适应字段探测 + 缓存）
index.html          单文件网页看板
trips.json          看板数据（当前为 120 条示例，带 demo 标记）
docs/               逆向分析报告（reverse-engineering-full-report.md 为终稿汇总）
recon/              分析与取证脚本（反汇编/unicorn 验证/假服务器/GDB），见 recon/README.md
MEMORY.md           逆向全过程工作日志（七轮）
```

APK 与 ninecli 二进制等大型原料不随仓库分发，再生成方法见 `recon/README.md`。

## 逆向结论速览

- 官方 APK（`cn.ninebot.ninebot` v6.x）被梆梆全量加固，静态反编译不可行；云 API 协议改从第三方 Go 客户端 **ninecli** 的二进制完整还原（含安全审计，未发现恶意代码）。
- 加密层：Passport 签名 = SHA256(排序参数)；业务请求 = AES-128-CBC（零 IV，PKCS7）+ RSA-1024 包裹密钥 + MD5 checkcode；响应经 DeriveKey（ROL8/XOR 自研公式）派生密钥解密后再解 wrapper。
- 关键接口：Passport `api-passport-bj.ninebot.com`、业务 `api-jhcx-v6-bj.ninebot.com`、行程 `POST /app-api/travel/v6/travel-list2` 与 `/app-api/travel/v6/travel-info`（注意 travel-list**2**）、车辆 `ebike.ninebot.com`。
- 行程列表自带最高速字段 `speed`；平均速 = 里程 ÷ 时长。
- 全部公式经 unicorn 执行二进制机器码 + GDB 断点抓包逐字节验证，详见 `docs/crypto-vs-disasm.md`。

## 注意事项

- 登录可能使手机端 App 会话失效，重新登录手机端即可恢复；建议数据仅供本人使用。
- 速度数据来自服务端下发的原始字段（列表即含最高速），平均速度 = 里程 ÷ 时长；
  若详情含逐点速度采样，脚本会用采样点重新计算并画曲线。
- 如果服务端字段名有变，`fetch_trips.py` 的 `KEY_*` 候选列表会自动探测，
  未识别的字段会原样保留在每条记录的 `raw`/`detail` 里。
