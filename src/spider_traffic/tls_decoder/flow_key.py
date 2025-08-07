#!/usr/bin/python
# encoding:utf-8


class FlowKey:
    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        if dst_port == 443:
            self.client = (src_ip, src_port)
            self.server = (dst_ip, dst_port)
        elif src_port == 443:
            self.client = (dst_ip, dst_port)
            self.server = (src_ip, src_port)
        else:
            # 手动比较两个端点，避免 sorted()
            if (src_ip, src_port) <= (dst_ip, dst_port):
                self.client = (src_ip, src_port)
                self.server = (dst_ip, dst_port)
            else:
                self.client = (dst_ip, dst_port)
                self.server = (src_ip, src_port)

    def reversed(self):
        return FlowKey(self.server[0], self.server[1], self.client[0], self.client[1])

    def __hash__(self):
        return hash((self.client, self.server))

    def __eq__(self, other):
        return self.client == other.client and self.server == other.server

    def __repr__(self):
        return f"{self.client[0]}:{self.client[1]} -> {self.server[0]}:{self.server[1]}"
