# Continuous Collection（连续采集子系统）

`spider_traffic.continuous` 是一个**不依赖 Scrapy** 的连续流量采集子系统：长时间持续抓包，
在 monitored 站点与 background 站点之间按比例随机混合访问，并为每一次访问写入 ground truth。

它与现有单 trace 流程（`main.py` / `action.py`）**完全独立**：不导入、不修改任何现有爬虫与
中间件代码，原有行为保持不变。

```text
调度决策 ──► 设置当小时 keylog ──► 浏览器访问 ──► 写 ground truth ──► 随机间隔
   ▲                                                                   │
   └──────────────────── 持续抓包（按小时切分 pcap）◄───────────────────┘
```

---

## 1. 第一阶段范围

| 维度 | 当前实现 |
| --- | --- |
| VPS 数量 | 1 个（配置里一个 `vps.name`，支持多份 YAML/多个 VPS 独立 seed 与状态） |
| 协议 | 仅 HTTPS（`sites.mode: https`，抓包过滤 `tcp port 443`） |
| 混合比例 | 可配置，示例 5%（支持 `1%` / `5%` / `10%` 或 `0.01` / `0.05` / `0.1`） |
| 抓包 | 单进程持续抓包，按小时切分 pcap（不再每次访问重启 tcpdump） |
| ground truth | 每次访问一行 JSON（JSONL） |
| 配置 | YAML |
| 容器 | `Dockerfile.continuous` + `continuous.sh` |

暂不支持（后续计划）：多 VPS 并行编排、HTTP/80 明文、代理（xray/tor）链路、访问后的截图与
页面内容落盘、PCAP 与 ground truth 的自动关联分析脚本。

---

## 2. 目录结构

```text
src/spider_traffic/continuous/
├── __init__.py          # 包说明
├── __main__.py          # python -m spider_traffic.continuous 入口
├── config.py            # YAML 加载、路径解析与校验
├── scheduling.py        # monitored/background 混合调度（比例、均衡、不放回）
├── sleeping.py          # 截断指数分布采样 + 可中断 sleep
├── capture.py           # 连续抓包 + 按小时切分 pcap
├── browser.py           # 复用 spider/ 下现有浏览器创建逻辑
├── groundtruth.py       # ground truth JSONL 写入
├── logging_setup.py     # 项目 logger（不可用时降级为控制台）
├── collector.py         # 主循环与命令行
└── README.md            # 本文档
```

### 复用与不复用的说明

| 能力 | 处理方式 |
| --- | --- |
| 浏览器创建 | **直接复用** `spider/chrome.py`、`spider/edge.py`、`spider/firefox.py` 的创建函数与 `spider/__init__.py::kill_browsers`，以及 `spider/chrome.py::scroll_to_bottom` |
| 路径/日志 | 复用 `myutils/__init__.py::project_path` 与 `myutils/logger.py` |
| 抓包 | **未直接调用** `traffic/capture.py::capture()`：它每次调用只产出一个文件、过滤器与 `SPIDER_MODE` 绑定、且不提供轮转与错误可见性；连续采集需要长跑 + 按小时切分，若强行复用就必须修改现有主流程。因此这里沿用它的参数风格与「terminate → 超时 → kill」收尾约定，独立实现生命周期管理 |

---

## 3. 快速开始

### 3.1 前置条件

```bash
# 依赖（新增 PyYAML）
. .venv/bin/activate && pip install -r requirements.txt

# 抓包权限（二选一）
sudo setcap cap_net_raw,cap_net_admin+eip "$(which tcpdump)"
sudo chown -R "$USER" logs data      # 历史上用 root 跑过会导致日志不可写
```

连续采集要求 `config/config.ini` 中 **`[spider] mode = direct`**（第一阶段只做 HTTPS 直连；
xray/tor 会让浏览器走代理，与 `tcp port 443` 的直连抓包不匹配，程序会直接报错退出）。

### 3.2 准备配置

```bash
cp config/continuous.example.yaml          config/continuous.yaml
cp config/continuous_monitored.example.txt config/continuous_monitored.txt
cp config/continuous_background.example.txt config/continuous_background.txt
# 然后按需修改这三个文件
```

站点列表每行一个主机名（`#` 为注释，也容忍 `https://example.com/` 写法，会自动归一化）。

### 3.3 先做 dry-run 验证

不启动浏览器、不抓包，只跑调度与日志，用来确认比例、均衡与产出路径：

```bash
./continuous.sh --dry-run --max-visits 50
# 或： cd src && ../.venv/bin/python3 -m spider_traffic.continuous --dry-run --max-visits 50
```

### 3.4 正式连续采集

```bash
./continuous.sh                                  # 持续运行，Ctrl-C 退出
./continuous.sh --max-visits 500                 # 跑 500 次访问后自动结束
./continuous.sh --seed 20260917 --vps vps-01     # 显式指定 seed 与 VPS 名（可复现）
```

程序会收到 `SIGINT`/`SIGTERM` 后**在当前访问结束后**优雅退出，并打印一份 JSON 汇总到 stdout。

### 3.5 查看产物

```bash
ls -la data/continuous/pcap/          # 按小时切分的 pcap
ls -la data/continuous/keylog/        # 与 pcap 同时间桶的浏览器 TLS keylog
tail -n 3 data/continuous/ground_truth.jsonl | python3 -m json.tool --json-lines
cat data/continuous/state/scheduler_state_vps-01.json   # 调度状态（可续跑）
```

---

## 4. 配置说明（YAML）

| 段 | 键 | 默认 | 说明 |
| --- | --- | --- | --- |
| `vps` | `name` | 必填 | VPS 名称；seed / 状态文件 / pcap 名都会带上它 |
| `vps` | `site` | `unknown` | 位置标签，仅用于日志与文件名 |
| `vps` | `seed` | `null` | 留空则首次运行自动生成并写入状态文件，重启后沿用；**每个 VPS 一份独立 seed** |
| `browser` | `name` | `chrome` | `chrome` / `edge` / `firefox` |
| `browser` | `settle_seconds` | `3.0` | 页面加载完成后的额外停留（秒） |
| `browser` | `page_load_timeout` | `60` | 单页加载超时（秒），超时按访问失败记录 |
| `browser` | `scroll` | `true` | 是否滚动加载 |
| `browser` | `ignore_system_proxy` | `true` | **直连采集必须保持 true**：移除 `http_proxy`/`https_proxy` 等环境变量。Firefox 默认「使用系统代理」会读取它们，若宿主机把代理指向本地 xray，浏览器就会走隧道（详见 6.4 与第 9 章） |
| `browser` | `visits_per_browser` | `20` | 浏览器常驻：同一个浏览器进程连续服务多少次访问后才重启（`1` = 每次访问都重启）；会话内复用同一标签页，cookie/缓存会话内共享（详见 6.5） |
| `sites` | `mode` | `https` | 第一阶段仅支持 `https` |
| `sites` | `monitored_file` | `config/continuous_monitored.txt` | monitored 站点列表 |
| `sites` | `background_file` | `config/continuous_background.txt` | background 站点列表 |
| `sites` | `monitored_ratio` | `0.05` | 支持 `5%`、`0.05` 两种写法 |
| `sites` | `ratio_mode` | `bernoulli` | `bernoulli`（每次独立随机）/ `exact`（长期比例精确） |
| `sites` | `background_sampling` | `shuffled_cycle` | `shuffled_cycle`（洗牌不放回）/ `random_choice`（有放回） |
| `sleep` | `distribution` | `truncated_exponential` | 目前仅支持截断指数 |
| `sleep` | `mean` / `min` / `max` | `20` / `3` / `90` | 单位秒；`mean` 是未截断指数分布的均值参数 |
| `capture` | `enabled` | `true` | 是否抓包 |
| `capture` | `tcpdump_binary` | `tcpdump` | 可指向自定义路径 |
| `capture` | `interface` | `null` | 留空用 tcpdump 默认网卡，例如 `eth0` |
| `capture` | `filter_expression` | `tcp port 443` | 抓包过滤表达式（过滤器会放在选项之后） |
| `capture` | `exclude_ports` | `[]` | 追加 `and not port N` |
| `capture` | `snaplen` | `0` | `0` 表示抓完整包 |
| `capture` | `extra_args` | `[]` | 追加 tcpdump 参数，例如 `["-U"]` |
| `capture` | `rotate_seconds` | `3600` | 文件切分周期，3600 = 按小时 |
| `capture` | `prefix` | `continuous` | pcap 文件名前缀 |
| `capture` | `output_dir` / `keylog_dir` | `data/continuous/...` | 产物目录 |
| `capture` | `stderr_log` | `logs/continuous_tcpdump.log` | tcpdump stderr 落盘（便于定位权限问题） |
| `storage` | `groundtruth_file` | `data/continuous/ground_truth.jsonl` | ground truth 追加写入 |
| `storage` | `state_dir` | `data/continuous/state` | 调度状态目录 |
| 根 | `max_visits` | `0` | 访问次数上限，`0` = 不限 |
| 根 | `log_every` | `10` | 每 N 次访问输出一次进度 |
| 根 | `dry_run` | `false` | 等价于命令行 `--dry-run` |

> **相对路径一律相对仓库根目录解析**，因此在任意工作目录运行结果一致。
>
> **浏览器级开关仍来自 `config/config.ini`**：`disable_quic`、`scroll_num`、代理设置等由现有
> 创建函数内部读取，本子系统不重复配置，也不修改它们。

### 命令行参数

| 参数 | 说明 |
| --- | --- |
| `--config PATH` | YAML 路径（默认 `<repo>/config/continuous.yaml`）；相对路径先按当前工作目录、再按仓库根目录依次尝试 |
| `--max-visits N` | 覆盖 YAML 的访问上限 |
| `--seed N` | 覆盖随机种子 |
| `--vps NAME` | 覆盖 VPS 名称 |
| `--dry-run` | 不抓包、不启动浏览器 |
| `--print-config` | 打印解析后的配置并退出 |
| `--log-level` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |

---

## 5. 调度策略

### 5.1 monitored 与 background 的混合比例

- `ratio_mode: bernoulli`（默认）：每次访问独立以概率 `p` 选择 monitored，间隔天然随机；
  这是有限样本下的随机抽样，实测比例会围绕 `p` 波动（例如 100 次访问、5% 时出现 3~9 次都正常）。
- `ratio_mode: exact`：用累加器保证长期比例精确等于 `p`（如 5% 时每 20 次访问恰好 1 次 monitored）。

两种模式都会在日志与汇总里给出**实际观测比例**，便于事后核对。

### 5.2 monitored 站点均衡

每次从「**历史访问次数最少**」的 monitored 站点中随机挑选一个（次数相同则随机打破平局）。
因此任意时刻各 monitored 站点的访问次数最多相差 1，长期完全均衡，且与比例无关。
进度日志会输出 `monitored 次数区间 [min, max]`。

### 5.3 background 站点采样

默认 `shuffled_cycle`：先把 background 列表随机打乱，按顺序取完一轮再重新洗牌 —— 即
「随机打乱后不放回采样」，同一轮内不会重复访问同一个站点，轮次交界处也不会与上一轮末尾相邻重复。
洗牌由 `(seed, cycle_index)` 确定性生成，所以状态文件只需记录轮次与偏移。

### 5.4 随机种子与状态续跑

- 种子优先级：`--seed` / YAML `vps.seed` > 状态文件 > 自动生成；
- 状态文件 `data/continuous/state/scheduler_state_<vps>.json` 每完成一次访问就原子写入，
  记录 seed、访问计数、monitored 每站计数、background 轮次与偏移；
- 重启后自动续跑：比例统计、monitored 均衡计数、background 轮次都不会重置；
- 不同 VPS 使用不同 `vps.name` 即拥有独立的状态文件与 seed，互不影响。

### 5.5 访问间隔

默认截断指数分布（`mean=20s`，`min=3s`，`max=90s`），用 inverse-CDF 直接采样（无拒绝循环）。
`mean` 是未截断指数分布的均值参数，截断后实际均值略小（启动日志会打印理论值，例如默认参数下约 21.9s）。
等待过程可被 `SIGINT`/`SIGTERM` 立即打断。

---

## 6. 抓包与产物

### 6.1 连续抓包与按小时切分

- 整个运行期间**只有一个 tcpdump 进程**，不会每次访问重启；
- 跨时间桶时自动 `terminate`（5 秒未退出则 `kill`）并启动新文件，日志会记录轮转与文件大小；
- 文件名：`<prefix>_<vps>_<YYYYmmdd_HHMMSS>.pcap`，其中时间戳是**该时间桶的起点**，
  `rotate_seconds=3600` 时即整点，例如 `continuous_vps-01_20260917_180000.pcap`；
- tcpdump 的 stderr 写入 `logs/continuous_tcpdump.log`；
- 启动后 0.5 秒内检测进程是否已退出：权限不足会立刻抛出可操作的错误（含 `setcap` 提示与 tcpdump 原始报错），
  而不是静默产生空 pcap。

### 6.2 TLS keylog

每次访问前把 `SSLKEYLOGFILE` 指向**当前时间桶**的 keylog 文件
`<keylog_dir>/sslkeys_<vps>_<YYYYmmdd_HHMMSS>.log`，因此 keylog 与 pcap 天然同桶对齐，
可直接用于离线解码（`pyshark ... tls.keylog_file:<该文件>`）。

### 6.3 ground truth 字段

每行一个 JSON：

| 字段 | 说明 |
| --- | --- |
| `visit_index` | 第几次访问（跨重启连续递增） |
| `vps` | VPS 名称 |
| `site` | 站点主机名 |
| `url` | 实际访问的 URL（`https://<site>`） |
| `category` | `monitored` 或 `background` |
| `start_time` / `end_time` | ISO8601，含时区，精确到毫秒 |
| `duration_seconds` | 本次访问耗时 |
| `success` | 成功/失败 |
| `error` / `error_type` | 失败时的错误信息与异常类型 |
| `landed_url` / `page_title` | 落地 URL 与页面标题（失败时可能为空） |
| `browser` | 使用的浏览器 |
| `pcap_file` | 访问**开始时**正在写入的 pcap 路径 |
| `pcap_file_at_end` | 访问**结束时**正在写入的 pcap（跨小时时与上一个不同） |
| `keylog_file` | 该时间桶的 keylog 路径 |
| `browser_session_id` | 第几个浏览器会话（从 1 开始；每 `visits_per_browser` 次访问递增） |
| `visit_in_session` | 该会话内的第几次访问（1..`visits_per_browser`） |
| `monitored_ratio_target` / `monitored_ratio_observed` | 目标比例与当时累计实际比例 |
| `dry_run` | 是否 dry-run 记录 |

### 6.4 直连保证（忽略系统代理）

Firefox 的 `network.proxy.type` 默认为 `5`（使用系统代理），在 Linux 上会读取
`http_proxy` / `https_proxy` / `all_proxy` 环境变量。如果宿主机把这些变量指向本地 xray
（本项目开发机上就是这种情况：`/usr/local/bin/xray` + `http://127.0.0.1:10809`），
那么即使 `config.ini` 是 `mode=direct`，浏览器仍会走隧道：

- 抓包里只有到**代理服务器**的 TLS（SNI 如 `<proxy-host>`），目标站点的 SNI 根本不会出现；
- 浏览器 keylog 记录的是"浏览器↔目标站点"的内层密钥，与抓到的外层隧道**无法配对**，离线解码必然为空。

因此 `browser.ignore_system_proxy`（默认 `true`）会在创建浏览器前移除这些环境变量，
启动日志会打印 `已忽略系统代理环境变量（保证直连）: http_proxy, https_proxy`。
开启后实测 SNI 为 `example.com` / `example.org`，且 pcap + keylog 可直接解码出资源。

> 单 trace 流程（`main.py`）没有这层保护：在本机这类环境下，它的 direct 模式同样会抓到隧道流量
> （历史 pcap 中看不到目标站点 SNI）。运行主流程前建议先 `unset http_proxy https_proxy`，
> 或另行决定是否为它加上同样的处理。

### 6.5 浏览器生命周期与复用（`visits_per_browser`）

默认策略：**浏览器常驻，每 20 次访问才重启一次**（`browser.visits_per_browser: 20`）。

```text
会话 #1 ── 访问 1..20 ──► 关闭 ──► 会话 #2 ── 访问 21..40 ──► 关闭 ──► 会话 #3 ── 访问 41..45 ──► 关闭
```

- **同一会话内复用同一个标签页**依次 `get` 每个 URL（与单 trace 流程的语义一致），
  访问前会关闭页面弹出的多余标签页，避免标签页/渲染进程堆积；
- `visits_per_browser: 1` 即恢复"每次访问都新建并关闭浏览器"的旧行为；
- 任何非 `TimeoutException` 的异常都会把浏览器标记为不可用，下一次访问自动重建；
- `TimeoutException`（页面加载超时）不影响会话继续使用。

这样做的收益（v6 上 45 次访问实测）：

| 指标 | 每次访问重启（`1`） | 每 20 次重启（`20`） |
| --- | --- | --- |
| 浏览器启动次数 | 45 | **3** |
| 每次访问的启动开销 | 0.53~0.61s | 摊薄到 1/20 |
| pcap 体积 / 443 包 | 9.06 MB / 4892 | **7.31 MB / 4094（−19%）** |
| 解码出的流数 | 98（目标 28 / 背景 70） | **65（目标 15 / 背景 50，−34%）** |
| 浏览器背景噪声 | 与访问次数成正比 | 与**会话数**成正比（45 次访问只触发 3 轮） |
| 渲染进程数 | 0↔12 反复 | 稳定 12~13，无泄漏 |
| 内存 | 访问间隙回落 | 常驻约 600 MiB（1.9 GB VPS 无压力） |

代价与注意：

- 同一会话内 **cookie / 缓存 / localStorage 共享**（同一次会话的 20 次访问视为同一浏览器身份），
  需要"每次访问都是全新访客"时请设 `visits_per_browser: 1`；
- 长会话下内存会常驻，不像逐次重启那样释放；内存紧张的 VPS 建议调小该值。

### 6.6 标签页策略：为什么不每次新开标签页

曾尝试每次访问 `switch_to.new_window("tab")`，实测发现 **Chrome 的新标签页（NTP/realbox）
会自行发起一批 Google 服务请求**，在 45 次访问的抓包里额外产生
`cse.google.com`、`syndicatedsearch.goog`、`adsensecustomsearchads.com`、`clients1.google.com`
等与目标站点无关的连接（每次新开标签页都触发一轮）。
改为复用同一标签页后，这些噪声降到"每个浏览器会话一次"，pcap 体积与流数同步下降（见 6.5 表格）。

---

## 7. Docker 运行

```bash
# 1) 先构建主镜像（含三浏览器 + tcpdump/tshark + venv）
docker build -t aimafan/spider_traffic:v1 .

# 2) 基于主镜像构建连续采集镜像（只替换入口）
docker build -f Dockerfile.continuous -t aimafan/spider_traffic:continuous .

# 3) 运行（抓包需 --privileged；直连采集用 --network host）
docker run --rm -it --privileged --network host \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  aimafan/spider_traffic:continuous -- --max-visits 500

# 4) 先 dry-run 验证
docker run --rm -it --network host \
  -v $(pwd)/config:/app/config -v $(pwd)/data:/app/data \
  aimafan/spider_traffic:continuous -- --dry-run --max-visits 50
```

要点：

- `--privileged` 用于 tcpdump 抓包；
- `--network host` 让容器内浏览器与抓包共用宿主网络栈；
- 挂载的 `config/` 里必须有 `continuous.yaml`、两个站点列表，且 `config.ini` 的 `mode=direct`；
- 通过环境变量 `CONTINUOUS_CONFIG` 可指定其它配置路径。

---

## 8. 已实测行为

在开发环境（Python 3.12、tshark 4.4.9、Firefox + geckodriver）中验证过：

| 验证项 | 结果 |
| --- | --- |
| 调度比例（bernoulli，10 万次访问，p=5%） | 实测 4.91%，符合预期波动 |
| 调度比例（exact，10 万次访问，p=5%） | 恰好 5000 次 = 5.0000% |
| monitored 均衡（10 万次，5 个站点） | 各站 982~983 次，极差 1 |
| background 不放回 | 每连续 12 次访问恰好覆盖 12 个不同站点 |
| 截断指数采样（20 万次，mean=20/3/90） | 全部落在 [3, 90]，均值 21.79s（理论 21.86s） |
| dry-run 端到端 | 45 次访问的 ground truth/状态文件正确生成并支持续跑 |
| 抓包轮转（伪 tcpdump） | 同桶不轮转、跨桶生成新文件名、keylog 同步换桶、命令顺序正确 |
| 抓包权限错误 | 抛出含 `setcap` 提示与 tcpdump 原始 stderr 的错误 |
| 真实浏览器访问 | 3 次访问成功，记录 `landed_url`/`page_title`，NSS 写出 keylog |
| **真实 tcpdump 抓包** | 4 次访问、`rotate_seconds=3`：生成 4 个真实 pcap（5.0/1.1/1.1/0.7 MB），443 包 3041/1298/1165/734，**非 443 包均为 0**（过滤器生效） |
| **抓包↔ground truth↔keylog 对齐** | 每次访问的 `pcap_file`/`keylog_file` 与实际文件一一对应，轮转日志与文件大小可核对 |
| **离线解码闭环** | 连续采集的 pcap + 同桶 keylog 交给项目自带解码器，得到 9 条资源（`example.com`/`example.org` status 200，含 size/ttfb）；`tshark` 亦解密出 HTTP/2 authority 与 path |
| **系统代理隔离** | 加固前抓到的只有代理域名 SNI；启用 `ignore_system_proxy` 后 SNI 变为 `example.com`/`example.org`，日志记录「已忽略系统代理环境变量」 |
| **VPS 真实部署（Debian 13 + Chromium 152）** | 45 次访问全部成功；dry-run 60 次；pcap/keylog/ground truth 三者在 `/opt/spider_traffic` 下闭环，解码出 89 flows / 189 resources（含 baidu/wikipedia 首页与静态资源） |
| **浏览器复用（每 20 次重启）** | 45 次访问只启动 **3 个**浏览器会话（20+20+5），日志逐次记录；`browser_session_id`/`visit_in_session` 可核对；渲染进程稳定 12~13 无泄漏，RAM 峰值 615 MiB |
| **标签页复用降低噪声** | 改为复用同一标签页后，同一配置的 pcap 由 9.06 MB/4892 包降到 7.31 MB/4094 包，解码流数由 98 降到 65（−34%），Chrome 新标签页触发的 Google 噪声降为每会话一次 |
| 配置校验 | monitored/background 重复站点、非法 mode/browser、`visits_per_browser < 1` 等均被明确拒绝 |

**真实抓包已验证**：在授予 `cap_net_raw,cap_net_admin` 的 tcpdump 副本下跑了完整的
真 tcpdump + 真浏览器流程，pcap 字节、按小时切分、ground truth 与 keylog 对齐、离线解码全部闭环。

---

## 9. 常见问题

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| 启动即 `PermissionError: logs/defult.log` | 日志文件属主为 root | `sudo chown -R "$USER" logs data`（dry-run 会自动降级为控制台日志，但真实访问仍需要修复） |
| `抓包启动失败：tcpdump 立即退出` | 无抓包权限 | `sudo setcap cap_net_raw,cap_net_admin+eip "$(which tcpdump)"` 或用 `--privileged` 容器 |
| `continuous HTTPS 模式要求 mode=direct` | `config.ini` 里是 xray/tor | 把 `[spider] mode` 改为 `direct` |
| 所有访问都失败且 `error=WebDriverException` | 浏览器或 driver 缺失/版本不匹配 | 安装 `bin/` 中的浏览器与 driver，或设置 `MSEDGE_BINARY`/`GECKODRIVER` 等环境变量 |
| pcap 文件为空 | 该小时内没有 443 流量（或 QUIC 未关闭） | 确认 `config.ini` 的 `disable_quic=true`、`capture.filter_expression` 与访问协议一致 |
| **pcap 里只有代理域名（如 `<proxy-host>`）的 SNI，没有目标站点** | 宿主机 `http_proxy`/`https_proxy` 指向本地 xray，Firefox 按系统代理走了隧道；抓到的只是隧道外层 TLS | 保持 `browser.ignore_system_proxy: true`（默认）；如仍出现，检查是否有 TUN 类全局代理 |
| 有 pcap 但解码不出资源 | keylog 与 pcap 不同桶（跨桶访问），或流量本就走隧道 | 用 ground truth 的 `keylog_file` 与 `pcap_file` 配对；先解决上一条 |
| 实际 monitored 比例偏离配置较多 | 样本太少（bernoulli 的随机波动） | 使用 `ratio_mode: exact`，或增大 `max_visits` |
| 想从头开始统计 | 状态文件保留计数 | 删除 `data/continuous/state/scheduler_state_<vps>.json` |

> ⚠️ 不要与单 trace 流程同时运行：两侧的浏览器清理函数使用 `pkill`，会互相杀掉对方的浏览器进程。

---

## 10. 后续计划

1. 多 VPS 编排与统一汇总（当前每个 VPS 一份 YAML + 独立状态目录即可手工并行）；
2. 运行结束时自动把当小时 keylog/pcap 与 ground truth 关联导出（例如按小时生成索引）；
3. 代理链路（xray/tor）下的连续采集与双层解码对接；
4. 访问截图/页面内容落盘（复用现有截图命名约定）；
5. 把「每分钟/每小时访问量、成功率、比例偏离」暴露为 Prometheus 指标或滚动报告。
