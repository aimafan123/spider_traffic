#!/usr/bin/python
# encoding:utf-8


class FlowKey:
    """
    A direction-agnostic key for a network flow.

    It canonizes the flow by sorting the two endpoints, ensuring that
    traffic from A to B and B to A results in the same key.
    """

    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        # 创建两个端点元组
        endpoint1 = (src_ip, int(src_port))
        endpoint2 = (dst_ip, int(dst_port))

        # 排序以创建规范化表示，保证键的唯一性
        if endpoint1 < endpoint2:
            self.endpoints = (endpoint1, endpoint2)
        else:
            self.endpoints = (endpoint2, endpoint1)

    def __hash__(self):
        return hash(self.endpoints)

    def __eq__(self, other):
        return isinstance(other, FlowKey) and self.endpoints == other.endpoints

    def __repr__(self):
        # 表示法也更新为方向无关的
        return f"Flow({self.endpoints[0][0]}:{self.endpoints[0][1]} <-> {self.endpoints[1][0]}:{self.endpoints[1][1]})"
