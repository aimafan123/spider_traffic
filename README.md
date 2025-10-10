# Spider Traffic - 智能流量捕获与分析系统

Spider Traffic 是一个集成了网络爬虫与流量捕获功能的高度自动化框架。它能够在多种代理模式（直连、Xray、Tor）下模拟浏览器行为，精确捕获和分析加密流量，并特别支持在直连模式下自动解码 HTTP/2 流量，为网络行为分析、安全研究和性能评测提供强大的数据支持。

## 🚀 核心特性

### 多模式流量捕获

- **直连模式 (Direct)**：直接连接目标网站，适用于常规流量分析
- **Xray代理模式**：通过 Xray 代理进行流量中继，支持 Trojan/VMess 协议
- **Tor匿名模式**：基于 Tor 网络进行匿名化访问

### 智能流量解码

- **TLS流量解密**：利用浏览器导出的 SSLKEYLOGFILE 自动解密 TLS 流量
- **HTTP/2协议解析**：完整解析 HTTP/2 帧结构，支持多路复用流重组
- **HTTP/1.1兼容**：同时支持传统 HTTP/1.1 协议解析
- **结构化输出**：将解析结果输出为标准 JSON 格式

### 自动化工作流

- **全程自动化**：从启动浏览器到流量解码，全程无需人工干预
- **任务队列管理**：支持批量 URL 处理，自动任务调度
- **智能超时控制**：可配置的页面加载和爬取时间限制
- **异常处理**：完善的错误处理和恢复机制

### 容器化部署

- **多系统支持**：提供 Ubuntu 20/24、Debian 12 等多版本 Dockerfile
- **特权模式运行**：支持网络流量捕获的特权容器部署
- **配置外挂**：支持配置文件和数据目录的外部挂载

## 📊 系统输出

### 1. 原始流量包 (.pcap)

- **全模式支持**：在所有代理模式下都会生成完整的网络流量包
- **标准格式**：符合 Wireshark 等工具的标准 PCAP 格式
- **完整捕获**：包含完整的网络通信数据，支持深度分析

### 2. 解码数据 (_decoded.json)

- **智能解码**：在直连模式下自动生成，包含解密后的 HTTP/2 资源信息
- **结构化数据**：以 JSON 格式清晰展示每个 TCP 流的详细信息
- **关联文件**：文件名与对应的 .pcap 文件自动关联

**JSON 输出示例：**

```json
{
    "['192.168.1.10', 54321, '104.18.32.123', 443]": {
        "sni": "example.com",
        "client_ip": "192.168.1.10",
        "resources": [
            {
                "stream_id": "1",
                "url": "https://example.com/",
                "request_data_size": 0,
                "resource_data_size": 25680
            },
            {
                "stream_id": "3",
                "url": "https://example.com/assets/main.css",
                "request_data_size": 0,
                "resource_data_size": 13450
            },
            {
                "stream_id": "http1-0",
                "url": "https://example.com/api/data",
                "request_data_size": 256,
                "resource_data_size": 1024
            }
        ]
    }
}
```

## 🛠️ 技术架构

### 核心模块

- **Main/Action**：主控制模块，负责整体流程协调
- **Spider**：基于 Scrapy + Playwright 的智能爬虫引擎
- **Traffic**：基于 tcpdump 的网络流量捕获模块
- **TLS Decoder**：TLS 流量解密和 HTTP/2 协议解析模块
- **MyUtils**：配置管理、日志记录等工具模块

### 技术栈

- **Python 3.9+**：主要开发语言
- **Scrapy 2.5+**：网络爬虫框架
- **Playwright 1.20+**：浏览器自动化
- **PyShark 0.6+**：网络包解析
- **Cryptography 3.4+**：加密解密支持
- **Docker**：容器化部署

## 📦 快速开始

### 环境要求

- Docker 20.10+
- Git LFS（用于大文件管理）
- Linux 系统（推荐 Ubuntu 20.04+）

### 1. 克隆项目

```bash
# 安装 Git LFS
sudo apt install git-lfs    # Ubuntu/Debian
# brew install git-lfs      # macOS

# 克隆项目
git clone --recurse-submodules https://github.com/aimafan123/spider_traffic.git
cd spider_traffic
git lfs pull
```

### 2. 构建 Docker 镜像

```bash
# 默认构建（Ubuntu 24.04）
docker build -t aimafan/spider_traffic:v1 .

# 使用其他系统版本
# Ubuntu 20.04
cp dockerfiles/Dockerfile.ubuntu20 ./Dockerfile
cp requirements/requirements_ubuntu20.txt ./requirements.txt
docker build -t aimafan/spider_traffic:ubuntu20 .

# Debian 12
cp dockerfiles/Dockerfile.debian12 ./Dockerfile
docker build -t aimafan/spider_traffic:debian12 .
```

### 3. 配置文件准备

```bash
# 创建配置目录
mkdir -p config data logs

# 配置主配置文件
cat > config/config.ini << EOF
[spider]
mode = direct
time_per_website = 300
download_delay = 3

[information]
name = spider_server
site = test_site
protocal = direct

[logging]
level = INFO
EOF

# 配置 URL 列表
cat > config/current_docker_url_list.txt << EOF
https://www.google.com
https://github.com
https://stackoverflow.com
EOF
```

### 4. 运行容器

```bash
# 基本运行
docker run --privileged --network host \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  aimafan/spider_traffic:v1

# 后台运行
docker run -d --privileged --network host \
  --name spider_traffic \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  aimafan/spider_traffic:v1
```

## ⚙️ 配置说明

### 主配置文件 (config/config.ini)

```ini
[spider]
mode = direct|xray|tor          # 运行模式
time_per_website = 300          # 单个网站爬取时间限制(秒)
download_delay = 3              # 请求间隔时间(秒)

[information]
name = server_name              # 服务器标识名称
site = site_name               # 站点标识名称
ip_addr = 192.168.1.100        # 本机IP地址(xray模式必需)
protocal = trojan|vmess|direct # 代理协议类型

[logging]
level = DEBUG|INFO|WARNING|ERROR # 日志级别
```

### URL 任务文件 (config/current_docker_url_list.txt)

```
https://www.example1.com
https://www.example2.com
http://httpbin.org/get
```

### Xray 配置文件 (config/config.json)

仅在 xray 模式下需要，配置代理服务器信息。

## 📈 使用场景

### 网络安全研究

- **流量分析**：深度分析网站的网络行为模式
- **协议研究**：研究 HTTP/2、TLS 等协议的实现细节
- **安全评估**：评估网站的安全配置和潜在风险

### 性能测试

- **加载性能**：分析网站资源加载的性能瓶颈
- **网络优化**：识别可优化的网络传输环节
- **CDN 分析**：分析 CDN 的分发效果和性能

### 学术研究

- **网络测量**：大规模网络行为测量和分析
- **协议演进**：跟踪和分析网络协议的发展趋势
- **隐私研究**：分析网站的数据收集和隐私保护机制

## 🔧 高级功能

### 自定义爬虫行为

通过修改 `spider/` 模块中的配置，可以自定义：

- 页面交互行为
- 资源过滤规则
- 爬取深度和广度
- 异常处理策略

### 流量过滤和分析

通过配置 tcpdump 参数，可以实现：

- 特定端口流量捕获
- 协议类型过滤
- IP 地址范围限制
- 数据包大小过滤

### 解码结果后处理

解码后的 JSON 数据支持：

- 自定义数据格式转换
- 统计分析和可视化
- 与其他分析工具集成
- 批量数据处理

## 🚨 注意事项

### 权限要求

- **特权模式**：容器需要以 `--privileged` 模式运行以支持网络捕获
- **网络权限**：需要 `--network host` 以访问宿主机网络接口
- **文件权限**：确保挂载目录具有正确的读写权限

### 系统资源

- **内存使用**：建议至少 2GB 可用内存
- **磁盘空间**：根据捕获流量大小预留足够磁盘空间
- **网络带宽**：确保网络连接稳定，避免捕获中断

### 法律合规

- **合法使用**：仅用于授权的网络和系统测试
- **隐私保护**：遵守相关的隐私保护法律法规
- **数据安全**：妥善保管捕获的敏感数据

## 📚 相关项目

- **部署项目**：[traffic_spider_bushu](https://github.com/ZGC-BUPT-aimafan/traffic_spider_bushu.git)
- **技术文档**：详见项目中的 `技术文档.md`

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request 来改进项目。在贡献代码前，请：

1. Fork 本项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件。

## 📞 联系方式

如有问题或建议，请通过以下方式联系：

- 提交 [GitHub Issue](https://github.com/aimafan123/spider_traffic/issues)
- 发送邮件至项目维护者

---

**Spider Traffic** - 让网络流量分析变得简单而强大 🕷️🌐
