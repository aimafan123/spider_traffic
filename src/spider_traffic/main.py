import json
import os
import shutil
import subprocess
import threading
import time

from spider_traffic.action import kill_chrome_processes, traffic
from spider_traffic.myutils import project_path
from spider_traffic.myutils.config import SPIDER_MODE, config
from spider_traffic.myutils.logger import logger
from spider_traffic.spider.task import task_instance
from spider_traffic.tls_decoder.http2decoder import TLSStreamDecoder
from spider_traffic.torDo import close_tor, start_tor


def run_action_script(traffic_path):
    command = ["../.venv/bin/python3", "-m", "spider_traffic.action", traffic_path]
    # 使用 subprocess 运行 action.py，模拟使用浏览器访问网站
    subprocess.run(command)


def browser_action():
    sslkeylog_file_path = "/tmp/sslkeys.log"
    os.environ["SSLKEYLOGFILE"] = sslkeylog_file_path
    VPS_NAME = config["information"]["name"]
    SITE_NAME = config["information"]["site"]

    # 检查SPIDER_MODE是否为有效值
    valid_modes = ["xray", "tor", "direct"]
    if SPIDER_MODE not in valid_modes:
        raise ValueError(
            f"Invalid SPIDER_MODE: {SPIDER_MODE}. Must be one of {valid_modes}."
        )

    if SPIDER_MODE == "xray":
        PROTOCAL_NAME = config["information"]["protocal"]
        xray_path = os.path.join(project_path, "bin", "Xray-linux-64", "xray")
        config_path = os.path.join(project_path, "config", "xray.json")
    elif SPIDER_MODE == "tor":
        PROTOCAL_NAME = config["information"]["protocal"]
    else:  # direct
        PROTOCAL_NAME = "direct"

    while True:

        def begin():
            # 开流量收集
            kill_chrome_processes()
            traffic_process, traffic_path = traffic(
                VPS_NAME, PROTOCAL_NAME, SITE_NAME, task_instance.current_start_url
            )
            # 开xray
            # 后台运行并脱离主程序
            if SPIDER_MODE == "xray":
                proxy_process = subprocess.Popen(
                    [xray_path, "run", "--config", config_path],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                logger.info(f"开启Xray程序，加载配置文件{config_path}")
                return traffic_process, proxy_process, True, traffic_path

            elif SPIDER_MODE == "tor":
                proxy_process, result = start_tor()

                return traffic_process, proxy_process, result, traffic_path

            else:
                return traffic_process, None, True, traffic_path

        def stop(traffic_process, proxy_process, traffic_path, result=True):
            if SPIDER_MODE == "xray":
                # 关xray
                proxy_process.terminate()  # 尝试优雅地关闭进程

                # 如果进程没有退出，使用kill强制终止
                try:
                    proxy_process.wait(timeout=5)  # 等待进程退出，最多等5秒
                except subprocess.TimeoutExpired:
                    proxy_process.kill()  # 如果进程没有在超时前退出，强制杀死进程
            elif SPIDER_MODE == "tor":
                close_tor(proxy_process)

            # 关流量收集
            traffic_process.terminate()  # 尝试优雅地关闭进程

            # 如果进程没有退出，使用kill强制终止
            try:
                traffic_process.wait(timeout=5)  # 等待进程退出，最多等5秒
                logger.info("优雅的关闭流量收集进程")
            except subprocess.TimeoutExpired:
                traffic_process.kill()  # 如果进程没有在超时前退出，强制杀死进程
                logger.info("强制杀死流量收集进程")
            if SPIDER_MODE == "tor" and result is not True:
                if os.path.exists(traffic_path):
                    os.remove(traffic_path)

        traffic_process, proxy_process, result, traffic_path = begin()
        if result is False:
            stop(traffic_process, proxy_process, traffic_path, False)
            continue

        if SPIDER_MODE == "tor":
            logger.info("等待tor网络稳定")
            time.sleep(60)

        action_thread = threading.Thread(target=run_action_script, args=(traffic_path,))
        # 启动线程
        action_thread.start()
        # 等待线程完成
        action_thread.join()

        time.sleep(3)
        logger.info("关闭浏览器进程")
        kill_chrome_processes()
        time.sleep(30)
        logger.info("等待流量结束")

        stop(traffic_process, proxy_process, traffic_path, True)

        # --- 保存SSLKEY文件并确保命名一致 ---
        sslkeylog_path = os.environ.get("SSLKEYLOGFILE")
        if sslkeylog_path and os.path.exists(sslkeylog_path):
            # 根据pcap文件名生成对应的sslkey文件名
            base_name = os.path.splitext(traffic_path)[0]
            sslkey_save_path = base_name + ".log"
            
            # 确保目标目录存在
            os.makedirs(os.path.dirname(sslkey_save_path), exist_ok=True)
            
            # 复制SSLKEY文件到与PCAP文件相同的目录，使用相同的基名
            shutil.copy2(sslkeylog_path, sslkey_save_path)
            logger.info(f"SSLKEY文件已保存至: {sslkey_save_path}")
        else:
            logger.warning(f"SSLKEYLOGFILE未找到或不存在: {sslkeylog_path}")

        # --- 新增的集成逻辑 ---
        # 如果是 direct 模式，则在流量收集结束后，调用解码器
        if SPIDER_MODE == "direct":
            logger.info(f"开始对 {traffic_path} 进行HTTP/2解码...")
            
            # 使用保存的SSLKEY文件进行解码
            saved_sslkey_path = os.path.splitext(traffic_path)[0] + ".log"
            
            if not os.path.exists(saved_sslkey_path):
                logger.error(f"保存的SSLKEY文件未找到于: {saved_sslkey_path}。跳过解码。")
            elif not os.path.exists(traffic_path):
                logger.error(f"Pcap文件未找到于: {traffic_path}。跳过解码。")
            else:
                try:
                    # 根据pcap文件名生成解码结果的json文件名
                    output_json_path = os.path.splitext(traffic_path)[0] + ".json"

                    # 实例化并运行解码器，使用保存的SSLKEY文件
                    decoder = TLSStreamDecoder(
                        pcap_file=traffic_path, sslkeylog_file=saved_sslkey_path
                    )
                    decoder.decode()
                    results = decoder.get_results()

                    # 将解码结果写入JSON文件
                    with open(output_json_path, "w", encoding="utf-8") as f:
                        json.dump(results, f, ensure_ascii=False, indent=4)
                    logger.info(f"HTTP/2解码完成，结果已保存至: {output_json_path}")

                except Exception as e:
                    logger.error(f"HTTP/2解码过程中发生错误: {e}", exc_info=True)
        # --------------------

        logger.info(f"第{str(task_instance.current_index)}个url爬取完成，爬取下一个url")
        task_instance.current_index = (
            task_instance.current_index + 1
        ) % task_instance.url_num
        running_path = os.path.join(project_path, "config", "running.json")
        with open(running_path, "w") as f:
            json.dump({"currentIndex": task_instance.current_index}, f)


if __name__ == "__main__":
    browser_action()
