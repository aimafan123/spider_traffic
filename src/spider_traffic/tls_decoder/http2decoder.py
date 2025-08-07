import json

import pyshark

from spider_traffic.myutils.logger import logger
from spider_traffic.tls_decoder.flow_key import FlowKey


class HTTP2Decoder:
    def __init__(self, pcap_file, sslkeylog_file, logger=logger):
        self.pcap_file = pcap_file
        self.sslkeylog_file = sslkeylog_file
        self.logger = logger
        self.connections = {}

    def decode(self):
        self.logger.debug(
            f"Start decoding {self.pcap_file} with SSLKEYLOG {self.sslkeylog_file}"
        )
        # 增加了对tls.handshake的过滤，确保能捕获到SNI
        capture = pyshark.FileCapture(
            self.pcap_file,
            display_filter="tls.handshake || http2",
            override_prefs={"tls.keylog_file": self.sslkeylog_file},
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

        # 首次见到该流，初始化连接信息
        if flow_key not in self.connections:
            self.connections[flow_key] = {"sni": None, "streams": {}}
            self.logger.debug(f"New connection: {repr(flow_key)}")

        # 尝试从TLS握手中提取SNI
        if "TLS" in pkt and not self.connections[flow_key]["sni"]:
            sni = self._get_sni(pkt)
            if sni:
                self.connections[flow_key]["sni"] = sni
                self.logger.debug(f"Found SNI for {repr(flow_key)}: {sni}")

        # 如果不是HTTP/2包，则处理完毕
        if "HTTP2" not in pkt:
            return

        conn_streams = self.connections[flow_key]["streams"]

        # 处理一个数据包中包含多个http2层的情况
        http2_layers = [layer for layer in pkt.layers if layer.layer_name == "http2"]
        for http2 in http2_layers:
            stream_id = getattr(http2, "streamid", None)
            frame_type = getattr(http2, "type", None)
            if stream_id is None or frame_type is None:
                continue

            # 根据帧类型进行处理
            if frame_type == "1":  # HEADERS frame
                self._process_headers_frame(
                    conn_streams, stream_id, http2, self.connections[flow_key]["sni"]
                )
            elif frame_type == "0":  # DATA frame
                self._process_data_frame(conn_streams, stream_id, http2, pkt, flow_key)

    def _parse_flow_key(self, pkt):
        try:
            # 同时支持IPv4和IPv6
            if hasattr(pkt, "ip"):
                src_ip, dst_ip = pkt.ip.src, pkt.ip.dst
            elif hasattr(pkt, "ipv6"):
                src_ip, dst_ip = pkt.ipv6.src, pkt.ipv6.dst
            else:
                return None

            if not hasattr(pkt, "tcp"):
                return None

            src_port, dst_port = int(pkt.tcp.srcport), int(pkt.tcp.dstport)
            return FlowKey(src_ip, src_port, dst_ip, dst_port)
        except AttributeError as e:
            self.logger.warning(
                f"Failed to parse flow key from packet {getattr(pkt, 'number', '?')}: {e}"
            )
            return None

    def _get_sni(self, pkt):
        try:
            # 字段路径为 tls.handshake_extensions_server_name
            return getattr(pkt.tls, "handshake_extensions_server_name", None)
        except AttributeError:
            return None  # 包中没有SNI字段

    def _process_headers_frame(self, conn_streams, stream_id, http2, sni):
        # 客户端请求的 HEADERS 帧不包含 :status 字段
        if not hasattr(http2, "headers_status"):
            domain = getattr(http2, "headers_authority", None)
            path = getattr(http2, "headers_path", None)

            if stream_id not in conn_streams:
                conn_streams[stream_id] = {
                    "domain": domain or sni,
                    "path": path,
                    "request_data_size": 0,
                    "resource_data_size": 0,
                }
            else:
                # 如果HEADERS帧后到，补充信息
                if domain:
                    conn_streams[stream_id]["domain"] = domain
                if path:
                    conn_streams[stream_id]["path"] = path
                if not conn_streams[stream_id].get("domain"):
                    conn_streams[stream_id]["domain"] = sni

    def _process_data_frame(self, conn_streams, stream_id, http2, pkt, conn_key):
        data_len = getattr(http2, "length", None)
        if not data_len:
            return

        try:
            size = int(data_len)
            # 如果DATA帧先于HEADERS帧到达，先初始化stream
            if stream_id not in conn_streams:
                conn_streams[stream_id] = {
                    "domain": None,
                    "path": None,
                    "request_data_size": 0,
                    "resource_data_size": 0,
                }

            # 判断数据方向来区分是请求数据还是响应数据
            pkt_src_ip = pkt.ip.src if hasattr(pkt, "ip") else pkt.ipv6.src
            pkt_src_port = int(pkt.tcp.srcport)

            if (pkt_src_ip, pkt_src_port) == conn_key.client:
                # 从客户端发往服务器的数据 -> 请求数据
                conn_streams[stream_id]["request_data_size"] += size
            else:
                # 从服务器发往客户端的数据 -> 资源数据
                conn_streams[stream_id]["resource_data_size"] += size
        except (ValueError, AttributeError) as e:
            self.logger.warning(
                f"Invalid data in DATA frame for stream {stream_id}: {e}"
            )

    def get_results(self):
        """
        处理捕获的数据，并返回一个按“流五元组”分组的资源字典，包含SNI作为独立层级。
        """
        results_by_flow = dict()

        # 遍历所有已记录的连接（流）
        for conn_key, conn_info in self.connections.items():
            # 从默认的 repr(conn_key) 修改为自定义的字符串格式
            # 假设 conn_key 对象有 src_ip, src_port, dst_ip, dst_port 属性
            # 先分割出源地址和目标地址
            conn_key = str(conn_key)
            src, dst = conn_key.split(" -> ")

            # 分别拆分IP和端口
            src_ip, src_port = src.split(":")
            dst_ip, dst_port = dst.split(":")

            # 构造最终列表，端口转换为整数
            flow_tuple_str = str([src_ip, int(src_port), dst_ip, int(dst_port)])

            sni = conn_info.get("sni") or "unknown"

            # 资源列表
            resources = []

            # 遍历该连接中的所有stream
            for stream_id, stream_info in conn_info["streams"].items():
                domain = stream_info.get("domain")
                path = stream_info.get("path")
                url = "incomplete_url"
                if domain and path:
                    url = f"https://{domain}{path}"
                elif domain:
                    url = f"https://{domain}/"

                resource_details = {
                    "stream_id": stream_id,
                    "url": url,
                    "request_data_size": stream_info.get("request_data_size", 0),
                    "resource_data_size": stream_info.get("resource_data_size", 0),
                }

                resources.append(resource_details)

            # 构建结果结构
            results_by_flow[flow_tuple_str] = {"sni": sni, "resources": resources}

        return results_by_flow


if __name__ == "__main__":
    pcap_path = "../test/test.pcap"
    sslkeylog_path = "../test/sslkeys.log"

    # 示例用法
    decoder = HTTP2Decoder(pcap_path, sslkeylog_path)
    decoder.decode()
    results = decoder.get_results()

    # 写入 JSON 文件
    with open("../test/results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=4)
