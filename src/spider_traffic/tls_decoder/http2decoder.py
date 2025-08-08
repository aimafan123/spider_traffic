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
        capture = pyshark.FileCapture(
            self.pcap_file,
            display_filter="tls.handshake || http2",
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

        if flow_key not in self.connections:
            self.connections[flow_key] = {"sni": None, "streams": {}}

        if "TLS" in pkt and not self.connections[flow_key]["sni"]:
            sni = self._get_sni(pkt)
            if sni:
                self.connections[flow_key]["sni"] = sni

        if "HTTP2" not in pkt:
            return

        conn_streams = self.connections[flow_key]["streams"]
        pkt_time = float(pkt.sniff_timestamp)

        http2_layers = [layer for layer in pkt.layers if layer.layer_name == "http2"]
        for http2 in http2_layers:
            stream_id = getattr(http2, "streamid", None)
            frame_type = getattr(http2, "type", None)
            if stream_id is None or frame_type is None:
                continue

            if stream_id not in conn_streams:
                conn_streams[stream_id] = {
                    "domain": None,
                    "path": None,
                    "status": None,
                    "content_type": None,
                    "request_data_size": 0,
                    "resource_data_size": 0,
                    "server_packet_count": 0,
                    "start_time": pkt_time,
                    "end_time": None,
                }

            if frame_type == "1":  # HEADERS
                self._process_headers_frame(
                    conn_streams, stream_id, http2, self.connections[flow_key]["sni"]
                )

            elif frame_type == "0":  # DATA
                self._process_data_frame(
                    conn_streams, stream_id, http2, pkt, flow_key, pkt_time
                )

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

            src_port, dst_port = int(pkt.tcp.srcport), int(pkt.tcp.dstport)
            return FlowKey(src_ip, src_port, dst_ip, dst_port)
        except AttributeError:
            return None

    def _get_sni(self, pkt):
        try:
            return getattr(pkt.tls, "handshake_extensions_server_name", None)
        except AttributeError:
            return None

    def _process_headers_frame(self, conn_streams, stream_id, http2, sni):
        domain = getattr(http2, "headers_authority", None)
        path = getattr(http2, "headers_path", None)
        status = getattr(http2, "headers_status", None)
        content_type = getattr(http2, "headers_content_type", None)

        if domain:
            conn_streams[stream_id]["domain"] = domain
        elif not conn_streams[stream_id]["domain"]:
            conn_streams[stream_id]["domain"] = sni

        if path:
            conn_streams[stream_id]["path"] = path
        if status:
            conn_streams[stream_id]["status"] = status
        if content_type:
            conn_streams[stream_id]["content_type"] = content_type

    def _process_data_frame(
        self, conn_streams, stream_id, http2, pkt, conn_key, pkt_time
    ):
        data_len = getattr(http2, "length", None)
        if not data_len:
            return

        try:
            size = int(data_len)
            pkt_src_ip = pkt.ip.src if hasattr(pkt, "ip") else pkt.ipv6.src
            pkt_src_port = int(pkt.tcp.srcport)

            if (pkt_src_ip, pkt_src_port) == conn_key.client:
                conn_streams[stream_id]["request_data_size"] += size
            else:
                conn_streams[stream_id]["resource_data_size"] += size
                conn_streams[stream_id]["server_packet_count"] += 1
                conn_streams[stream_id]["end_time"] = pkt_time
        except ValueError:
            return

    def get_results(self):
        results_by_flow = {}

        for conn_key, conn_info in self.connections.items():
            conn_key_str = str(conn_key)
            sni = conn_info.get("sni") or "unknown"

            resources = []
            for stream_id, s in conn_info["streams"].items():
                url = "incomplete_url"
                if s["domain"] and s["path"]:
                    url = f"https://{s['domain']}{s['path']}"
                elif s["domain"]:
                    url = f"https://{s['domain']}/"

                latency = None
                if s["start_time"] and s["end_time"]:
                    latency = s["end_time"] - s["start_time"]

                resources.append(
                    {
                        "stream_id": stream_id,
                        "url": url,
                        "status": s["status"],
                        "content_type": s["content_type"],
                        "request_data_size": s["request_data_size"],
                        "resource_data_size": s["resource_data_size"],
                        "server_packet_count": s["server_packet_count"],
                        "latency": latency,
                    }
                )

            results_by_flow[conn_key_str] = {"sni": sni, "resources": resources}

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
