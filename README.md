# Spider Traffic

**浏览器驱动的加密流量采集与 TLS 分析框架。**

Spider Traffic 用真实浏览器访问目标站点，同时抓取原始报文并导出 TLS 会话密钥，最终产出可离线复现、可深度分析的网络测量数据：`pcap`、TLS keylog、页面截图和资源级解码 JSON。

它的目标不是抓取业务数据，而是回答"**这个网站到底加载了什么、用了什么协议、耗时如何**"。

> 📖 更完整的架构、模块、配置、解码原理与问题清单，见 [`项目文档.md`](项目文档.md)。

---

## 目录

- [核心特性](#核心特性)
- [工作原理](#工作原理)
- [系统架构](#系统架构)
- [仓库结构](#仓库结构)
- [环境要求](#环境要求)
- [快速开始](#快速开始)
- [配置说明](#配置说明)
- [运行与输出](#运行与输出)
- [三种运行模式](#三种运行模式)
- [流量解码](#流量解码)
- [连续采集 Continuous Collection](#连续采集-continuous-collection)
- [Docker 部署](#docker-部署)
- [常见问题排查](#常见问题排查)
- [已知限制](#已知限制)
- [二次开发](#二次开发)
- [安全与合规](#安全与合规)

---

## 核心特性

| 特性 | 说明 |
| --- | --- |
| 🌐 真实浏览器访问 | 支持 `chrome`、`edge`、`firefox`，headless 运行，可配置滚动加载 |
| 🕸️ 站内链接爬取 | Scrapy 负责调度与链接发现，Selenium 负责页面加载 |
| 📦 原始流量抓取 | `tcpdump` 抓包，按站点分目录归档 |
| 🔑 TLS 密钥导出 | 通过 `SSLKEYLOGFILE` 导出浏览器会话密钥，支持离线解密 |
| 🔍 资源级解码 | HTTP/1.1 与 HTTP/2 重建：URL、状态码、MIME、请求/响应大小、耗时、TTFB |
| 🧩 隧道解码 | Xray(Trojan) 外层剥离 + 内层二次解码 |
| 🔀 多代理模式 | `direct` 直连 / `xray` 代理 / `tor` 洋葱网络 |
| 🐳 容器化运行 | 提供 Dockerfile 与多发行版变体，内置浏览器与代理二进制 |
| 📊 结构化输出 | 解码结果为标准 JSON，便于下游统计与可视化 |

---

## 工作原理

单个站点的一轮采集流程：

```text
读取当前目标（config/current_docker_url_list.txt + config/running.json）
        │
        ├─ 1. 清理残留浏览器进程
        ├─ 2. 启动 tcpdump 抓包 ──────────────────────────► data/pcap/<host>/*.pcap
        ├─ 3. 按模式启动代理（Xray / Tor，direct 模式跳过）
        ├─ 4. 启动 action.py 子进程 → Scrapy 引擎
        │        └─ Selenium 打开页面 → 滚动 → 截图 ──────► data/screenshot/...
        │             └─ 浏览器写出 SSLKEYLOGFILE ────────► /tmp/sslkeys.log
        ├─ 5. 到达时限后停止爬虫、强杀浏览器、等待尾部流量
        ├─ 6. 关闭代理与抓包进程
        ├─ 7. 归档密钥：/tmp/sslkeys.log → <pcap>.log
        └─ 8. is_decode=true 时离线解码 ──────────────────► <pcap>.json
```

关键点：**Scrapy 不发起真实网络请求**。下载中间件直接用 Selenium 打开 URL，并把 `page_source` 包装成 `HttpResponse` 返回，因此页面加载、渲染、资源请求全部由真实浏览器完成。

---

## 系统架构

```text
                         ┌──────────────────────┐
                         │      main.py         │  无限循环 / 进程编排
                         └───┬──────────┬───────┘
              subprocess     │          │ Popen / terminate
        ┌────────────────────┘          └──────────────┐
        ▼                                              ▼
┌──────────────────┐                        ┌─────────────────────┐
│   action.py      │  抓包 + Scrapy          │ tcpdump / Xray / Tor │
│  (每站一个子进程) │                        └─────────────────────┘
└────────┬─────────┘
         ▼
┌──────────────────────────────┐
│ spider/middlewares.py        │  Selenium 下载中间件
│  · 计数限流(webnum)           │
│  · browser.get + 滚动 + 截图  │
└────────┬─────────────────────┘
         ▼
┌──────────────────────────────┐
│ Chrome / Edge / Firefox      │  headless + SSLKEYLOGFILE + 代理
└────────┬─────────────────────┘
         ▼
┌──────────────────────────────┐
│ tls_decoder/                 │
│  http2decoder.py   → direct  │
│  TrojanDecoder.py  → xray    │
└──────────────────────────────┘
```

---

## 仓库结构

```text
spider_traffic/
├── action.sh                    # 单 trace 流程启动脚本
├── continuous.sh                # 连续采集启动脚本
├── Dockerfile                   # 主构建文件（Ubuntu + 三浏览器）
├── Dockerfile.continuous        # 连续采集镜像（基于主镜像，仅替换入口）
├── dockerfiles/                 # ubuntu20 / ubuntu24 / debian12 变体
├── requirements.txt             # Python 依赖
├── requirements/                # 按发行版区分的依赖
├── config/                      # 运行配置（不入库，需自行准备；示例文件除外）
├── data/                        # 抓包、截图等产物
├── logs/                        # 运行日志
├── bin/                         # 浏览器 / driver / Xray / Tor 二进制（不入库）
├── test/                        # 样例 pcap 与 keylog（不入库）
└── src/
    ├── scrapy.cfg
    └── spider_traffic/
        ├── main.py              # 总控编排：进程管理 + 密钥归档 + 解码调度
        ├── action.py            # 单站任务：抓包 + Scrapy 运行
        ├── torDo.py             # Tor 启动 / 关闭 / 引导等待
        ├── myutils/             # 路径、配置、日志
        ├── spider/
        │   ├── task.py          # 任务单例：URL 列表、下标、过滤词
        │   ├── settings.py      # Scrapy 配置
        │   ├── middlewares.py   # Selenium 下载中间件（核心）
        │   ├── spiders/trace.py # 唯一的 Spider（链接发现）
        │   ├── chrome.py / edge.py / firefox.py   # 浏览器适配
        ├── traffic/capture.py   # tcpdump 抓包封装
        ├── continuous/          # 连续采集子系统（不依赖 Scrapy，见其 README）
        └── tls_decoder/
            ├── flow_key.py      # 方向无关流键
            ├── http2decoder.py  # HTTP/1.1 + HTTP/2 解码器
            └── TrojanDecoder.py # Trojan 外层剥离 + 内层解码
```

---

## 环境要求

| 项目 | 要求 |
| --- | --- |
| 操作系统 | Linux（依赖 `pkill`、`/tmp`、`tcpdump`） |
| Python | 3.12（当前开发环境 3.12.3） |
| 抓包工具 | `tcpdump`（需 root 或 `CAP_NET_RAW`） |
| 解析工具 | `tshark`（pyshark 依赖，建议 4.x） |
| 浏览器 | Chrome / Edge / Firefox 及对应 driver（`bin/` 中提供） |
| 目录权限 | `logs/`、`data/`、`config/` 必须可写 |

> 仓库中的 `bin/`、`config/`、`data/`、`logs/`、`test/` 均被 `.gitignore` 忽略，**克隆后不能直接运行**，需要补齐配置与二进制。

---

## 快速开始

### 1. 安装依赖

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Python 依赖之外还需要系统提供 `tcpdump` 与 `tshark`：

```bash
sudo apt install -y tcpdump tshark
```

### 2. 授予抓包权限

```bash
# 方案 A：给 tcpdump 加 capabilities（推荐）
sudo setcap cap_net_raw,cap_net_admin+eip "$(which tcpdump)"

# 方案 B：以 root 运行（注意 -E 保留环境变量）
sudo -E .venv/bin/python3 -m spider_traffic.main
```

> ⚠️ 若曾用 root 运行过，`logs/` 下文件会变成 root 所有，普通用户再次运行会在启动时直接报 `PermissionError`。用 `sudo chown -R "$USER" logs data` 修复。

### 3. 准备配置

创建 `config/config.ini`：

```ini
[information]
name = local_node          ; 节点标识，用于 pcap 文件名
protocal = direct          ; 协议名；xray/tor 模式下填实际协议（trojan 才触发隧道解码）
site = lab                 ; 位置标识
ip_addr = 127.0.0.1        ; xray 模式抓包过滤用（代理服务器 IP）

[proxy]
host = 127.0.0.1
port = 10809               ; 必须与 Xray / Tor 实际监听端口一致

[spider]
browser = firefox          ; chrome | edge | firefox
time_per_website = 30      ; 单站爬取时限（秒）
download_delay = 60        ; 请求间隔（秒）
mode = direct              ; direct | xray | tor
scroll = true              ; 是否滚动加载
scroll_num = 3             ; 最大滚动次数
webnum = 1                 ; 每站最大请求数，-1 表示不限
disable_quic = true        ; 关闭 QUIC，保证流量可解密
is_decode = true           ; 采集后是否自动解码
```

准备目标列表 `config/current_docker_url_list.txt`：

```text
# 每行一个「主机名」，不要写 https://
baidu.com
zhihu.com
bilibili.com
```

准备过滤词 `config/exclude_keywords`（命中则不跟随该链接）：

```text
login
register
account
help
policy
```

初始化任务下标 `config/running.json`：

```json
{"currentIndex": 0}
```

### 4. 运行

```bash
./action.sh
# 等价于：
cd src && ../.venv/bin/python3 -m spider_traffic.main
```

启动脚本要求**当前工作目录是仓库根**，且虚拟环境位于仓库根的 `.venv/`。

---

## 配置说明

### `config/config.ini`

| 段 | 键 | 类型 | 说明 |
| --- | --- | --- | --- |
| `information` | `name` | str | 节点名，写入 pcap 文件名 |
| `information` | `site` | str | 位置标签，写入 pcap 文件名 |
| `information` | `protocal` | str | xray/tor 模式下的协议名；`trojan` 才会走隧道解码 |
| `information` | `ip_addr` | str | xray 模式抓包过滤的主机（代理服务器 IP） |
| `proxy` | `host` / `port` | str / int | 浏览器代理地址，需与 Xray/Tor 监听端口一致 |
| `spider` | `mode` | enum | `direct` / `xray` / `tor`，进程启动时读取 |
| `spider` | `browser` | enum | `chrome` / `edge` / `firefox`，默认 `chrome` |
| `spider` | `time_per_website` | int | 单站爬取时限（秒） |
| `spider` | `download_delay` | int | Scrapy 请求间隔（秒） |
| `spider` | `webnum` | int | 每站最大请求数，`-1` 为不限 |
| `spider` | `scroll` / `scroll_num` | bool / int | 是否滚动、最大滚动次数 |
| `spider` | `disable_quic` | bool | 关闭 HTTP/3，提高可解码比例 |
| `spider` | `is_decode` | bool | 是否在采集后自动解码 |

> 配置中的 `depth`、`multisite_num` 目前没有任何代码引用，可以删除。

### 代理配置

| 模式 | 需要准备的文件 | 说明 |
| --- | --- | --- |
| `direct` | 无 | 浏览器直连目标站点 |
| `xray` | `config/xray.json` | 程序固定读取该文件名，可 `cp config/xray_trojan.json config/xray.json` |
| `tor` | `config/torrc` | Tor 配置文件，`SocksPort` 需与 `[proxy] port` 一致 |

Xray 配置中与项目相关的两个要点：

1. `inbounds` 的 http 代理端口要与 `config.ini` 的 `[proxy] port` 一致；
2. 出口的 `streamSettings.tlsSettings.masterKeyLog` 应指向 `/tmp/xray_sslkeylog.log`，程序会把它归档为 `<pcap>.xray.log`。

---

## 运行与输出

### 产物

| 产物 | 路径 |
| --- | --- |
| 原始抓包 | `data/pcap/<host>/<协议>_<时间戳>_<节点>_<位置>_<host>.pcap` |
| 浏览器密钥 | `<pcap 同名>.log` |
| Xray 外层密钥 | `<pcap 同名>.xray.log`（仅 xray 模式） |
| 解码结果 | `<pcap 同名>.json`（`is_decode=true`） |
| 页面截图 | `data/screenshot/<host>/<pcap 文件名>.png` |
| 主程序日志 | `logs/defult.log`（滚动，50 MB × 3） |
| URL 访问日志 | `logs/url.log` |
| Scrapy 日志 | `logs/scrapy_<年>_<月>_<日>.log` |

pcap 命名示例：

```text
data/pcap/baidu.com/direct_20260320170144_<node-ip>_<site>_baidu.com.pcap
```

### 单站耗时

```text
单站耗时 ≈ time_per_website + 3s(缓冲) + 30s(等待流量收尾) + 浏览器启动时间
tor 模式额外固定等待 60s（等待 Tor 网络稳定）
```

即默认配置下每站约 **65 秒起步**；程序以无限循环方式轮转 URL，没有正常退出路径，用 `Ctrl-C` 或容器停止结束。

### 解码结果示例

```json
{
  "Flow(<server-ip>:443 <-> <client-ip>:57760)": {
    "sni": "illinois.edu",
    "resources": [
      {
        "stream_id": "http1-0",
        "url": "https://illinois.edu/",
        "status": "200",
        "content_type": "text/html; charset=UTF-8",
        "request_data_size": 0,
        "resource_data_size": 60768,
        "headers_packet_num": 70082,
        "request_packet_nums": [70082],
        "response_packet_nums": [70482],
        "request_time": 1757486672.502325,
        "response_start_time": 1757486673.144609,
        "response_end_time": 1757486673.144609,
        "duration_sec": 0.6422839164733887,
        "ttfb_sec": 0.6422839164733887
      }
    ]
  }
}
```

字段含义：

| 字段 | 说明 |
| --- | --- |
| 顶层键 | 方向无关的流标识 `Flow(ip:port <-> ip:port)` |
| `sni` | TLS ClientHello 中的目标域名 |
| `stream_id` | HTTP/2 流 ID，或 HTTP/1.1 的伪流 ID `http1-<n>` |
| `url` | 由 authority/host + path 重建，统一为 `https://` |
| `status` / `content_type` | 响应状态码与 MIME |
| `request_data_size` / `resource_data_size` | 请求体与响应体字节数（解密后、未解压） |
| `*_packet_nums` | 对应的抓包序号，可在 Wireshark 中跳转 |
| `duration_sec` | 末个响应数据 − 请求时间 |
| `ttfb_sec` | 首个响应数据 − 请求时间（HTTP/1.1 下与 `duration_sec` 相等） |

---

## 三种运行模式

| 维度 | `direct` | `xray` | `tor` |
| --- | --- | --- | --- |
| 代理 | 无 | Xray（HTTP 代理） | Tor（SOCKS5） |
| 抓包范围 | 全量（排除 22/80 端口） | 仅与代理服务器之间的流量 | 全量（排除 22/80 端口） |
| 解密 | HTTP/1.1 + HTTP/2 | Trojan 隧道内层重建 | 无内置解码 |
| 产物 | `.pcap` `.log` `.json` | `.pcap` `.log` `.xray.log` `.json` | `.pcap` `.log` |
| 适用场景 | 需完整资源级分析的测量 | 研究代理隧道内部行为 | 采集墙外可达性/连通性 |

---

## 流量解码

### 解密原理

浏览器通过 `SSLKEYLOGFILE` 导出 TLS 会话密钥，`pyshark` 调用 `tshark` 时以 `tls.keylog_file` 载入这些密钥，即可解密并重组 HTTPS 流量：

```python
pyshark.FileCapture(
    pcap_file,
    display_filter="tls.handshake || http2 || http",
    override_prefs={"tls.keylog_file": sslkeylog_file},
)
```

### 支持范围

| 协议 / 特性 | 支持 |
| --- | --- |
| HTTPS over TLS 1.2 / 1.3（TCP） | ✅ |
| HTTP/1.1 | ✅ |
| HTTP/2（HEADERS / DATA） | ✅ |
| 明文 HTTP(80) | ❌（抓包阶段已排除） |
| QUIC / HTTP3 | ❌（默认关闭 QUIC） |
| HTTP/2 推送、CONTINUATION | ❌ |
| ECH / 加密 SNI | ❌ |
| WebSocket / gRPC | ❌ |

### Trojan 隧道解码

```text
pcap
 └─ tshark -z follow,tls,raw,<i>   （用 <pcap>.xray.log 解外层）
     └─ scapy 重建内层 TCP/TLS 流
         └─ TLSStreamDecoder          （用 <pcap>.log 解内层）
             └─ <pcap>.json
```

> 该链路依赖 tshark `follow,tls,raw` 的输出格式，属于仓库中最实验性的部分；重建包的时间戳为构造时间，因此内层时延指标无真实网络意义。

---

## 连续采集 Continuous Collection

除上面的单 trace 流程外，仓库还提供 `src/spider_traffic/continuous/` **连续采集子系统**
（第一阶段：HTTPS 直连）。它与单 trace 流程完全独立，不导入也不修改现有爬虫代码。

| 能力 | 说明 |
| --- | --- |
| 无 Scrapy | 直接复用 `spider/` 下现有的浏览器创建逻辑，每次访问独立浏览器会话 |
| 混合访问 | monitored 与 background 站点按比例随机混合（支持 1% / 5% / 10%，两种比例模式） |
| monitored 均衡 | 每次选访问次数最少的站点，任意时刻各站次数差 ≤ 1 |
| background 不放回 | 默认洗牌后按轮次取完再洗牌（可切换为有放回随机） |
| 随机间隔 | 默认截断指数分布：mean=20s、min=3s、max=90s，采样可被信号打断 |
| 独立 seed | 每个 VPS 一份 seed 与状态文件，重启自动续跑 |
| 持续抓包 | 单个 tcpdump 连续运行，按小时切分 pcap，keylog 与 pcap 同桶对齐 |
| ground truth | 每次访问一行 JSON：站点、类别、起止时间、耗时、成功/失败、pcap/keylog 路径 |

```bash
# 准备配置与站点列表
cp config/continuous.example.yaml          config/continuous.yaml
cp config/continuous_monitored.example.txt config/continuous_monitored.txt
cp config/continuous_background.example.txt config/continuous_background.txt

./continuous.sh --dry-run --max-visits 50   # 先验证调度与日志（不抓包、不开浏览器）
./continuous.sh                             # 正式连续采集，Ctrl-C 优雅退出
```

产物：`data/continuous/pcap/`、`data/continuous/keylog/`、`data/continuous/ground_truth.jsonl`、
`data/continuous/state/`。

完整配置说明、调度策略、字段定义与 Docker 用法见
[`src/spider_traffic/continuous/README.md`](src/spider_traffic/continuous/README.md)；
容器入口见 [`Dockerfile.continuous`](Dockerfile.continuous)。

---

## Docker 部署

### 构建

```bash
docker build -t aimafan/spider_traffic:v1 .
```

> 默认 `Dockerfile` 的基础镜像指向内网私有仓库，外部环境请先替换 `FROM` 行。`bin/` 下的浏览器与 driver 安装包是构建必需项。

### 运行

```bash
docker run --rm -it --privileged --network host \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  aimafan/spider_traffic:v1 \
  bash -lc "cd /app/src && ../.venv/bin/python3 -m spider_traffic.main"
```

说明：

- `--privileged` 用于 `tcpdump` 抓包；
- `--network host` 让容器直连宿主机网络与本地代理端口；
- 需要容器内浏览器与 driver 版本匹配，否则 Selenium 会无法建立会话；
- 如需更精确的时延测量，可在容器内先关闭网卡合并：
  `sudo ethtool -K eth0 tso off gso off gro off`

多发行版变体在 `dockerfiles/` 下（`Dockerfile_ubuntu20`、`Dockerfile_ubuntu24`、`Dockerfile_debian12`），其中仅主线 `Dockerfile` 安装了 Chrome、Edge、Firefox 三套浏览器。

---

## 常见问题排查

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| 启动即 `PermissionError: logs/defult.log` | 日志文件属主为 root | `sudo chown -R "$USER" logs data` |
| 启动即 `KeyError: 'spider'` | `config/config.ini` 缺失或段名错误 | 按[配置说明](#配置说明)补齐 |
| 没有生成 pcap | 抓包权限不足 | 配置 `setcap` 或以 root 运行 |
| pcap 为 0 字节 | tcpdump 启动失败（权限/网卡） | 手工执行 tcpdump 命令确认报错 |
| 没有 `<pcap>.log` | 浏览器未写出密钥 | 检查 `SSLKEYLOGFILE` 是否被继承、浏览器是否正常启动 |
| JSON 为空 `{}` | keylog 与 pcap 不匹配 | 确认解码时 keylog 与 pcap 同名同批 |
| JSON 中大量 `resources: []` | 只握手或单向的埋点流量 | 正常现象，可加最小资源数阈值过滤 |
| 只抓到了首页 | `webnum=1`（默认） | 调大 `webnum` 或设为 `-1` |
| xray 模式请求全部失败 | 代理端口与 `xray.json` 不一致 | 对齐 `[proxy] port` 与 Xray inbound 端口 |
| `FileNotFoundError: 未找到 ... driver` | driver 不在 PATH | 将 `bin/` 中对应 driver 复制到 `/usr/local/bin` |

更多排障条目见 [`项目文档.md` 第 12 章](项目文档.md#12-排障手册)。

---

## 已知限制

- **URL 输入是主机名**，不是完整 URL，程序内部硬编码拼接 `https://`；
- 抓包显式排除 **22 与 80 端口**，明文 HTTP 不在采集范围；
- **QUIC 默认关闭**，若开启会导致大量流量无法解密；
- Xray/Tor 的配置文件（`config/xray.json`、`config/torrc`）**需自行准备**，仓库未提供；
- `tor` 模式**没有解码链路**，仅完成采集；
- 站点选择依赖 `running.json` 文件下标，**单实例、无并发调度**；
- 历史实现中部分依赖（Playwright、Splash 等）未被引用，属于依赖膨胀；
- 仓库目前**没有自动化测试**，`test/` 仅为样例数据。

完整的风险清单与修复建议见 [`项目文档.md` 第 11 章](项目文档.md#11-已知问题与风险清单)。

---

## 二次开发

### 代码规范

- 遵循 PEP 8，4 空格缩进，UTF-8 源文件；
- 函数/变量/模块用 `snake_case`，类用 `PascalCase`；
- 避免在 import 期产生副作用，可执行逻辑放在 `if __name__ == "__main__":`；
- 统一使用 `myutils/logger.py` 的 `logger` 输出日志，不直接 `print`。

### 扩展方向

- **新增浏览器**：在 `spider/` 增加模块 → 注册到 `spider/__init__.py` 的 `BROWSER_CLEANERS`、`middlewares.py` 的 `browser_creators`、`main.py` 的 `valid_browsers`；
- **新增协议解码**：在 `tls_decoder/` 增加解码器，保持输出结构 `{flow: {sni, resources[]}}`，并在 `main.py` 的解码分发处注册；
- **补充测试**：建议优先为解码器加回归测试（可直接复用 `test/test.pcap` + `test/sslkeys.log`）。

### 提交规范

```text
feat: ...      # 新功能
fix: ...       # 缺陷修复
refactor: ...  # 重构
docs: ...      # 文档
chore: ...     # 杂项
```

每次提交聚焦一类改动；涉及配置变更时请说明新增/修改的键，并附验证命令与产物路径。

---

## 安全与合规

本项目处理的是**高度敏感**的数据：

- 原始抓包（完整 URL、Cookie、响应体）
- TLS 会话密钥（可解密对应流量）
- 代理服务器地址与凭据
- 网络拓扑与节点信息

请务必：

1. **不要**将 `config/`、`data/`、`logs/`、`test/`、`*.tar` 提交或推送到任何远程仓库；
2. 分享截图、日志、pcap 前先脱敏（域名、IP、URL、凭据）；
3. 对采集到的密钥与流量及时加密归档或销毁；
4. 仅在**获得明确授权**的网络与目标上执行抓包和代理访问。

---

## 相关文档

| 文档 | 内容 |
| --- | --- |
| [`项目文档.md`](项目文档.md) | 完整项目文档：架构、模块、配置、数据格式、解码原理、验证记录、风险清单、排障手册 |
| [`技术文档.md`](技术文档.md) | 早期技术文档（部分内容已与代码不一致） |
| [`项目分析报告.md`](项目分析报告.md) | 架构分析与改进建议 |
| [`AGENTS.md`](AGENTS.md) | 仓库协作规范 |
| [`CHANGELOG.md`](CHANGELOG.md) | 更新日志 |

---

## 许可证

仓库历史文档中提及 MIT 许可证，但当前根目录下没有 `LICENSE` 文件；如需以 MIT 条款发布或再分发，请先补充许可证文件。
