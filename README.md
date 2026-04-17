V2Ray Node Real-IP Scanner
这是一个基于 Python 开发的高性能、轻量级 V2Ray 节点深度检测工具。它不仅能验证节点的连通性，还能穿透代理真实检测出口 IP、地理位置及 Google 访问状态。

✨ 核心特性
多协议解析：支持 VLESS (含 Reality) 与 VMess 链接的自动化解析。

深度并发检测：利用 Python 线程池实现高效并发扫描，大幅提升多节点检测速度。

真实落地识别：通过局部代理环境，实时调用多源接口（ip.sb / ip-api）获取出口 IP 与详细地理位置。

Google 状态验证：精准模拟访问请求，通过状态码判断节点对 Google 服务的支持程度。

智能资源管理：

动态端口分配：随机分配本地 SOCKS5 端口，有效规避进程冲突。

自动清理：程序运行结束后自动释放 Xray 进程并清除临时配置文件。

🚀 快速上手
1. 准备环境
Python 3.8+

将 xray.exe 核心文件放置在脚本同级目录下。

2. 安装依赖
Bash
pip install requests pyperclip
3. 运行程序
Bash
python v2rayN真实地址.py
🛠️ 技术栈
GUI 框架：Tkinter (优化版 UI)

内核驱动：Xray-core

并发模型：concurrent.futures.ThreadPoolExecutor

网络库：Requests (配合 socks5h 协议)

⚠️ 免责声明
本工具仅用于网络环境诊断与技术研究。请使用者在法律允许的范围内使用，并自觉遵守当地法律法规。
