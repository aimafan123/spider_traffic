import binascii
import json
import os
import random
import re
import subprocess
from collections import defaultdict
from typing import Any, Dict, Optional

from pyshark.tshark.tshark import get_process_path
from scapy.all import IP, TCP, Ether, Raw, wrpcap

from spider_traffic.myutils import project_path
from spider_traffic.myutils.logger import logger
from spider_traffic.tls_decoder.flow_key import FlowKey
from spider_traffic.tls_decoder.http2decoder import TLSStreamDecoder


class TrojanDecoder:
    def __init__(self, pcap_path, out_keylog_path, tls_keylog, json_path):
        self.pcap_path = pcap_path
        self.out_keylog_path = out_keylog_path
        self.tls_keylog = tls_keylog
        self.json_path = json_path
        self.decoded_pcap_path = None
        self.connections: Dict[FlowKey, Dict[str, Any]] = {}
        self.trace_results = {}

    def run(self):
        """主运行方法：解码PCAP文件并生成TLS流数据"""
        # 调用TrojanDecoder的process_pcap和save_keylog方法
        self._out_decoder_pcap()
        self.save_results_to_json()

    def _create_pcap_from_hex_file(self):
        """
        创建TCP三次握手，然后从文本文件中读取十六进制TLS数据并创建pcap文件。
        文件中的缩进行表示客户端到服务器的流量，
        未缩进行表示服务器到客户端的流量。
        """
        if not os.path.exists("/tmp/raw_hex.txt"):
            print(f"错误: 输入文件 '/tmp/raw_hex.txt' 未找到。")
            print("请确保该文件与脚本在同一目录下。")
            return
        with open("/tmp/raw_hex.txt", "r") as f:
            lines = f.readlines()
        # --- 1. 自动解析IP和端口 ---
        stream_info = self._parse_stream_info(lines)
        if stream_info:
            client_ip = stream_info["client"]["ip"]
            client_port = stream_info["client"]["port"]
            server_ip = stream_info["server"]["ip"]
            server_port = stream_info["server"]["port"]
        else:
            logger.error("错误: 无法解析流信息。")
            return

        packets = []

        # --- 2. 创建 TCP 三次握手 ---
        client_isn = random.randint(0, 2**32 - 1)
        server_isn = random.randint(0, 2**32 - 1)

        syn = (
            Ether()
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=client_port, dport=server_port, flags="S", seq=client_isn)
        )
        syn_ack = (
            Ether()
            / IP(src=server_ip, dst=client_ip)
            / TCP(
                sport=server_port,
                dport=client_port,
                flags="SA",
                seq=server_isn,
                ack=syn.seq + 1,
            )
        )
        ack = (
            Ether()
            / IP(src=client_ip, dst=server_ip)
            / TCP(
                sport=client_port,
                dport=server_port,
                flags="A",
                seq=syn.seq + 1,
                ack=syn_ack.seq + 1,
            )
        )
        packets.extend([syn, syn_ack, ack])

        # --- 3. 准备数据传输的序列号 ---
        client_seq = ack.seq
        server_seq = ack.ack

        is_first_data_packet = True
        # --- 4. 循环构建数据包 ---
        for i, line in enumerate(lines, 1):
            hex_string = "".join(line.split())
            if not hex_string or "====" in hex_string or ":" in hex_string:
                continue

            try:
                if is_first_data_packet:
                    # 为了更精确，我们查找 '1603' (TLS Handshake Record)
                    start_index = hex_string.find("160301")
                    if start_index > 0:  # > 0 表示前面有前缀
                        prefix = hex_string[:start_index]
                        hex_string = hex_string[start_index:]

                    is_first_data_packet = False  # 处理完后，将标志设为False
                payload = bytes.fromhex(hex_string)
                is_client_to_server = len(line) != len(line.lstrip())

                if is_client_to_server:
                    packet = (
                        Ether()
                        / IP(src=client_ip, dst=server_ip)
                        / TCP(
                            sport=client_port,
                            dport=server_port,
                            flags="PA",
                            seq=client_seq,
                            ack=server_seq,
                        )
                        / Raw(load=payload)
                    )
                    client_seq += len(payload)
                else:
                    packet = (
                        Ether()
                        / IP(src=server_ip, dst=client_ip)
                        / TCP(
                            sport=server_port,
                            dport=client_port,
                            flags="PA",
                            seq=server_seq,
                            ack=client_seq,
                        )
                        / Raw(load=payload)
                    )
                    server_seq += len(payload)

                packets.append(packet)

            except ValueError:
                # 智能跳过非十六进制行（如文件头部的元数据）
                # print(f"   (跳过第 {i} 行非数据内容)")
                continue

        # --- 4. 写入 Pcap 文件 ---
        self.decoded_pcap_path = "/tmp/decoded_tls.pcap"
        output_filename = os.path.join(
            os.path.dirname(self.pcap_path), self.decoded_pcap_path
        )
        try:
            wrpcap(output_filename, packets)
            logger.debug(f"Pcap 文件已成功生成: {output_filename}")
        except Exception as e:
            logger.error(f"写入pcap文件时发生错误: {e}")

    def _parse_stream_info(self, lines):
        """从文件行中解析Node信息并确定客户端/服务器。"""
        node_info = {}
        # 1. 解析Node行
        node_pattern = re.compile(r"Node\s+(\d+):\s+([\d.]+):(\d+)")
        for line in lines:
            match = node_pattern.match(line)
            if match:
                node_id, ip, port = match.groups()
                node_info[int(node_id)] = {"ip": ip, "port": int(port)}

        if len(node_info) < 2:
            return None  # 未找到足够的Node信息

        # 2. 找到第一个数据行并判断方向
        for line in lines:
            hex_string = "".join(line.split())
            if not hex_string:
                continue
            try:
                bytes.fromhex(hex_string)
                # 找到第一个有效的数据行
                is_indented = len(line) != len(line.lstrip())
                # Node 1 是 Wireshark 中第二个出现的节点，通常是客户端
                # 缩进行也是客户端发出的
                if is_indented:
                    return {"client": node_info[1], "server": node_info[0]}
                else:
                    return {"client": node_info[0], "server": node_info[1]}
            except ValueError:
                continue  # 跳过非十六进制行

        return None  # 没有找到有效的数据行

    def _out_decoder_pcap(self):
        """
        使用 pyshark 库来跟踪 pcap 文件中所有的 TLS 流，
        生成解密后的PCAP文件用于后续分析。
        """

        for i in range(999999):
            cmd = [
                get_process_path(),
                "-r",
                self.pcap_path,
                "-o",
                f"tls.keylog_file:{self.out_keylog_path}",
                "-q",
                "-z",
                f"follow,tls,raw,{i}",
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)
            if "Node 0: :0" in result.stdout:
                break
            with open("/tmp/raw_hex.txt", "w") as f:
                f.write(result.stdout)
            self._create_pcap_from_hex_file()

            decoder = TLSStreamDecoder(self.decoded_pcap_path, self.tls_keylog)
            decoder.decode()
            results = decoder.get_results()
            # 多个字典合起来，构成一个json文件
            self.trace_results.update(results)

    def save_results_to_json(self):
        """将结果保存到JSON文件"""
        try:
            with open(self.json_path, "w", encoding="utf-8") as f:
                json.dump(self.trace_results, f, ensure_ascii=False, indent=4)
            logger.info(f"结果已保存到: {self.json_path}")
        except Exception as e:
            logger.error(f"保存JSON文件时出错: {e}")


def action(pcap_path: str, keylog_path: str, tls_keylog: str, json_path: str):
    """
    主要的处理函数，用于解码PCAP文件并生成JSON结果

    Args:
        pcap_path: PCAP文件路径
        keylog_path: 外层trojan共享密钥日志路径
        tls_keylog: TLS密钥日志文件路径
        json_output_path: JSON输出文件路径（可选）
    """
    decoder = TrojanDecoder(pcap_path, keylog_path, tls_keylog, json_path)
    decoder.run()


if __name__ == "__main__":
    pcap_path = os.path.join(project_path, "wiki_trojan", "64.pcap")
    out_keylog_path = os.path.join(
        project_path, "wiki_trojan", "xray_sslkeylog_server.log"
    )
    tls_keylog = os.path.join(project_path, "wiki_trojan", "sslkeys.log")

    json_path = os.path.join(project_path, "wiki_trojan", "result.json")

    action(pcap_path, out_keylog_path, tls_keylog, json_path)
