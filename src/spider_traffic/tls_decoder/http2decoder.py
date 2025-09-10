import json

import pyshark
from typing import Dict, Any

from spider_traffic.myutils.logger import logger
from spider_traffic.tls_decoder.flow_key import FlowKey


# 类名修改为更通用的名字，因为它现在同时支持 HTTP/1.1 和 HTTP/2
class TLSStreamDecoder:
    """
    Decodes TLS-encrypted traffic from a PCAP file using an SSLKEYLOG file,
    supporting both HTTP/1.1 and HTTP/2 protocols.

    It reconstructs requests and responses, associating them with their
    respective TCP flows.
    """

    def __init__(self, pcap_file, sslkeylog_file, logger=logger):
        self.pcap_file = pcap_file
        self.sslkeylog_file = sslkeylog_file
        self.logger = logger
        # connections 结构保持不变，但其内部的 streams 将包含两种协议的数据
        self.connections: Dict[FlowKey, Dict[str, Any]] = {}

    def decode(self):
        self.logger.debug(
            f"Start decoding {self.pcap_file} with SSLKEYLOG {self.sslkeylog_file}"
        )

        ### MODIFIED ###
        # 修改 display_filter，增加 'http' 来捕获解密的 HTTP/1.1 流量
        capture = pyshark.FileCapture(
            self.pcap_file,
            display_filter="tls.handshake || http2 || http",
            override_prefs={"tls.keylog_file": self.sslkeylog_file},
            keep_packets=False,
        )

        for pkt in capture:
            try:
                self._process_packet(pkt)
            except Exception as e:
                self.logger.warning(
                    f"Error parsing packet {getattr(pkt, 'number', '?')}: {e}"
                )

        capture.close()
        self.logger.debug(f"Decoding done: {len(self.connections)} connections found")

    def _process_packet(self, pkt):
        flow_key = self._parse_flow_key(pkt)
        if flow_key is None:
            return

        # 初始化连接信息
        if flow_key not in self.connections:
            try:
                client_ip = pkt.ip.src if hasattr(pkt, "ip") else pkt.ipv6.src
                self.connections[flow_key] = {
                    "sni": None,
                    "streams": {},
                    "client_ip": client_ip,
                    "http1_unmatched_req_count": 0, # 用于HTTP/1.1请求响应匹配
                }
            except AttributeError:
                return

        conn = self.connections[flow_key]

        # 提取 SNI
        if "TLS" in pkt and not conn["sni"]:
            sni = self._get_sni(pkt)
            if sni:
                conn["sni"] = sni

        ### MODIFIED ###
        # 协议分发逻辑
        if "HTTP2" in pkt:
            self._process_http2_packet(pkt, flow_key)
        elif "HTTP" in pkt:
            # pyshark 会将 HTTP/1.1 的数据包标记为 'http' 协议层
            self._process_http1_packet(pkt, flow_key)

    ### NEW ###
    def _process_http1_packet(self, pkt, flow_key):
        """处理解密的 HTTP/1.1 数据包"""
        conn = self.connections[flow_key]
        conn_streams = conn["streams"]
        pkt_time = float(pkt.sniff_timestamp)
        pkt_num = int(pkt.number)

        http = pkt.http
        is_request = hasattr(http, "request_method")

        if is_request:
            # 对于每个请求，我们创建一个新的“流”来追踪它
            # 使用一个计数器作为 HTTP/1.1 的伪流ID
            stream_id = f"http1-{conn['http1_unmatched_req_count']}"
            conn["http1_unmatched_req_count"] += 1

            # 初始化流结构
            conn_streams[stream_id] = self._create_empty_stream()

            domain = getattr(http, "host", conn["sni"])
            path = getattr(http, "request_uri", "/")

            stream = conn_streams[stream_id]
            stream.update({
                "domain": domain,
                "path": path,
                "request_time": pkt_time,
                "headers_packet_num": pkt_num,
                "request_packet_nums": [pkt_num],
            })
            # 处理请求体大小 (例如 POST 请求)
            if hasattr(http, "content_length"):
                stream["request_data_size"] = int(http.content_length)

        else: # 是响应
            # 寻找最近的、还没有匹配到响应的 HTTP/1.1 请求
            target_stream_id = None
            for i in range(conn["http1_unmatched_req_count"] -1, -1, -1):
                s_id = f"http1-{i}"
                if s_id in conn_streams and conn_streams[s_id]["status"] is None:
                    target_stream_id = s_id
                    break

            if target_stream_id:
                stream = conn_streams[target_stream_id]
                stream.update({
                    "status": getattr(http, "response_code", None),
                    "content_type": getattr(http, "content_type", None),
                    "response_packet_nums": [pkt_num], # 因为pyshark已重组，一个包代表一个响应
                    "response_start_time": pkt_time,
                    "response_end_time": pkt_time,
                })
                # file_data 字段包含了重组后的响应体
                if hasattr(http, "file_data"):
                    # 计算响应体大小
                    stream["resource_data_size"] = len(bytes.fromhex(http.file_data.replace(":", "")))

    ### NEW ###
    def _process_http2_packet(self, pkt, flow_key):
        """处理 HTTP/2 数据包 (逻辑从旧的 _process_packet 迁移而来)"""
        conn = self.connections[flow_key]
        conn_streams = conn["streams"]
        pkt_time = float(pkt.sniff_timestamp)
        pkt_num = int(pkt.number)

        http2_layers = [layer for layer in pkt.layers if layer.layer_name == "http2"]
        for http2 in http2_layers:
            stream_id = getattr(http2, "streamid", None)
            frame_type = getattr(http2, "type", None)
            if stream_id is None or frame_type is None:
                continue

            if stream_id not in conn_streams:
                conn_streams[stream_id] = self._create_empty_stream()

            if frame_type == "1":  # HEADERS
                self._process_http2_headers_frame(
                    conn_streams,
                    stream_id,
                    http2,
                    conn["sni"],
                    pkt_num,
                    pkt_time,
                )
            elif frame_type == "0":  # DATA
                self._process_http2_data_frame(
                    conn_streams,
                    stream_id,
                    http2,
                    pkt,
                    conn["client_ip"],
                    pkt_num,
                    pkt_time,
                )

    ### NEW ###
    def _create_empty_stream(self):
        """创建一个用于存储流数据的标准空字典结构"""
        return {
            "domain": None,
            "path": None,
            "status": None,
            "content_type": None,
            "request_data_size": 0,
            "resource_data_size": 0,
            "headers_packet_num": None,
            "request_packet_nums": [],
            "response_packet_nums": [],
            "request_time": None,
            "response_start_time": None,
            "response_end_time": None,
        }

    def _parse_flow_key(self, pkt):
        try:
            if hasattr(pkt, "ip"):
                src_ip, dst_ip = pkt.ip.src, pkt.ip.dst
            elif hasattr(pkt, "ipv6"):
                src_ip, dst_ip = pkt.ipv6.src, pkt.ipv6.dst
            else:
                return None

            if not hasattr(pkt, "tcp"):
                return None

            src_port, dst_port = pkt.tcp.srcport, pkt.tcp.dstport
            return FlowKey(src_ip, src_port, dst_ip, dst_port)
        except AttributeError:
            return None

    def _get_sni(self, pkt):
        try:
            return getattr(pkt.tls, "handshake_extensions_server_name", None)
        except AttributeError:
            return None

    ### MODIFIED ###
    # 重命名以明确其仅用于 HTTP/2
    def _process_http2_headers_frame(
        self, conn_streams, stream_id, http2, sni, pkt_num, pkt_time
    ):
        domain = getattr(http2, "headers_authority", None)
        path = getattr(http2, "headers_path", None)
        status = getattr(http2, "headers_status", None)
        content_type = getattr(http2, "headers_content_type", None)

        stream = conn_streams[stream_id]

        if path: # 包含 path 的 HEADERS 帧通常是请求
            stream["headers_packet_num"] = pkt_num
            stream["request_time"] = pkt_time

        if domain:
            stream["domain"] = domain
        elif not stream["domain"]:
            stream["domain"] = sni

        if path:
            stream["path"] = path
        if status:
            stream["status"] = status
        if content_type:
            stream["content_type"] = content_type

    ### MODIFIED ###
    # 重命名以明确其仅用于 HTTP/2
    def _process_http2_data_frame(
        self, conn_streams, stream_id, http2, pkt, client_ip, pkt_num, pkt_time
    ):
        data_len = getattr(http2, "length", None)
        if not data_len:
            return

        try:
            size = int(data_len)
            pkt_src_ip = pkt.ip.src if hasattr(pkt, "ip") else pkt.ipv6.src
            stream = conn_streams[stream_id]

            if pkt_src_ip == client_ip: # 请求数据
                stream["request_data_size"] += size
                stream["request_packet_nums"].append(pkt_num)
            else: # 响应数据
                stream["resource_data_size"] += size
                stream["response_packet_nums"].append(pkt_num)

                if stream["response_start_time"] is None:
                    stream["response_start_time"] = pkt_time
                stream["response_end_time"] = pkt_time

        except (ValueError, AttributeError):
            return

    def get_results(self):
        results_by_flow = {}

        for conn_key, conn_info in self.connections.items():
            conn_key_str = str(conn_key)
            sni = conn_info.get("sni") or "unknown"

            resources = []
            # 现在 conn_info["streams"] 中混合了 HTTP/1.1 和 HTTP/2 的数据
            for stream_id, s in conn_info["streams"].items():
                # 过滤掉不完整的流 (例如，只有请求没有响应)
                if not s["response_packet_nums"] or s["status"] is None:
                    continue

                url = "incomplete_url"
                if s["domain"] and s["path"]:
                    # 确保 URL 格式正确
                    protocol = "https" # 我们只处理解密的HTTPS
                    host = s["domain"]
                    path = s["path"]
                    url = f"{protocol}://{host}{path}"
                elif s["domain"]:
                    url = f"https://{s['domain']}/"
                
                # 计算延迟
                duration = None
                if s["request_time"] and s["response_end_time"]:
                    duration = s["response_end_time"] - s["request_time"]

                time_to_first_byte = None
                if s["request_time"] and s["response_start_time"]:
                    time_to_first_byte = s["response_start_time"] - s["request_time"]

                resources.append(
                    {
                        "stream_id": stream_id,
                        "url": url,
                        "status": s["status"],
                        "content_type": s["content_type"],
                        "request_data_size": s["request_data_size"],
                        "resource_data_size": s["resource_data_size"],
                        "headers_packet_num": s["headers_packet_num"],
                        "request_packet_nums": sorted(s["request_packet_nums"]),
                        "response_packet_nums": sorted(s["response_packet_nums"]),
                        "request_time": s["request_time"],
                        "response_start_time": s["response_start_time"],
                        "response_end_time": s["response_end_time"],
                        "duration_sec": duration,
                        "ttfb_sec": time_to_first_byte,
                    }
                )

            # 按请求时间排序，更好地模拟瀑布图
            sorted_resources = sorted(
                resources, key=lambda r: r.get("request_time") or float("inf")
            )

            results_by_flow[conn_key_str] = {"sni": sni, "resources": sorted_resources}

        return results_by_flow


if __name__ == "__main__":
    # 假设 test.pcap 同时包含 HTTP/1.1 和 HTTP/2 的加密流量
    pcap_path = "../test/test.pcap"
    sslkeylog_path = "../test/sslkeys.log"

    # 示例用法
    decoder = TLSStreamDecoder(pcap_path, sslkeylog_path)
    decoder.decode()
    results = decoder.get_results()

    # 写入 JSON 文件
    with open("../test/results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=4)
    
    print("Decoding complete. Results saved to ../test/results.json")