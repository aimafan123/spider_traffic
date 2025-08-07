# 流量捕获系统Spider Traffic

Spider Traffic 是一个集成了网络爬虫与流量捕获功能的高度自动化框架。它能够在多种代理模式（直连、Xray、Tor）下模拟浏览器行为，精确捕获和分析加密流量，并特别支持在直连模式下自动解码 HTTP/2 流量，为网络行为分析、安全研究和性能评测提供强大的数据支持。

## 核心功能
### 网络爬取与流量采集

- 全自动工作流: 从启动浏览器、执行访问、捕获流量到关闭进程，全程无需人工干预。
- 多代理模式支持:
    - direct 模式: 直接连接目标网站，适用于常规流量分析。
    - xray 模式: 通过 Xray 代理进行流量中继，支持复杂的路由和协议。
    - tor 模式: 基于 Tor 网络进行匿名化访问。
- 精准的流量捕获: 使用 tcpdump 在底层捕获指定网络接口的全部流量，并保存为标准的 .pcap 文件。
- 自动化 HTTP/2 解码 (new!): 在 direct 模式下，系统能够利用浏览器导出的 SSLKEYLOGFILE 自动解密并解析捕获到的 TLS 流量，提取出 HTTP/2 的详细请求数据（如 URL、请求/响应大小等），并将其结构化为 JSON 文件。
- 灵活的 Docker 部署: 提供多版本操作系统的 Dockerfile，支持快速构建和迁移。

## 系统输出
系统运行后，您将获得两种核心产物：
1. 原始流量包 (.pcap):
- 在所有模式下，系统都会生成 .pcap 文件。
- 这些文件包含了完整的网络通信数据，可以使用 Wireshark 等工具进行深度分析。

2. HTTP/2 解码数据 (_decoded.json):
- 仅在 direct 模式下自动生成，文件名与对应的 .pcap 文件关联（例如 traffic_xxx.json）。
- 该文件以 JSON 格式清晰地展示了每个 TCP 流（Flow）中解密后的 HTTP/2 资源信息。

JSON 文件结构示例:

```JSON
{
    "['192.168.1.10', 54321, '104.18.32.123', 443]": {
        "sni": "example.com",
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
            }
        ]
    }
}
```

## 构建 Docker 镜像

在开始使用之前，首先需要构建Docker镜像。在有`dockerfile`的目录下执行以下命令来构建镜像（对应不同的操作系统、以及相同操作系统的不同版本有不同的`dockerfile`，默认为`ubuntu24`，其中`dockerfiles`目录中有`ubuntu20、debian12`版本的操作系统，如有需要可以将其替换为`spider_traffic`目录下的`dockerfile`）：
> 注意！！
> 如果安装的是`ubuntu20`，那么还需要在创建镜像之前将`requirements.txt`文件进行修改，可替换为`requirements`文件夹中的`requirements_ubuntu20.txt`，`txt`文件名保持和`spider_traffic`中一致的文件名；

由于本仓库中 `bin/google-chrome-stable_current_amd64.deb` 由git lfs托管，所以需要通过git lfs正确拉去该安装包

1. 安装git-lfs
```bash
sudo apt install git-lfs    // debian/ubuntu
brew install git-lfs        // mac
```

2. 克隆项目
```bash
git clone --recurse-submodules https://github.com/aimafan123/spider_traffic.git
cd spider_traffic
git lfs pull
```

3. 构建镜像
```bash
docker build -t aimafan/spider_traffic:v1 .
```

## 部署说明
该项目的部署可以参考服务部署项目：[traffic_spider_bushu](https://github.com/ZGC-BUPT-aimafan/traffic_spider_bushu.git) 。



### Dockerfile 说明

在使用Dockerfile文件打包镜像之前，需要修改第一行采用的基底镜像