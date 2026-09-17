#!/bin/bash
# Continuous Collection 本地启动脚本
#
# 用法：
#   ./continuous.sh                         # 使用 config/continuous.yaml 持续采集
#   ./continuous.sh --dry-run --max-visits 50
#   ./continuous.sh --config config/other.yaml
#
# 注意：抓包需要 root 或 tcpdump capabilities，见 continuous/README.md。
set -euo pipefail

cd "$(dirname "$0")/src"
exec ../.venv/bin/python3 -m spider_traffic.continuous "$@"
