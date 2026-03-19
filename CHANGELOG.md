# 更新日志

## 2026-03-19（74f76fb，相比 2cb62e6）

### 改进
- 增加浏览器类型配置读取：从 `config["spider"]["browser"]` 读取运行浏览器，默认值为 `chrome`。
- 增加浏览器参数校验：支持 `chrome`、`edge`、`firefox`，非法值会抛出明确错误，避免后续流程异常。
- 优化浏览器进程清理逻辑：将固定的 `kill_chrome_processes()` 改为 `kill_browsers(browser_name)`，在开始抓包前和任务结束后都按当前浏览器类型清理，降低残留进程风险。

### 影响文件
- `src/spider_traffic/main.py`
