import tkinter as tk
from tkinter import ttk, messagebox
import json
import base64
import requests
import subprocess
import time
import os
import pyperclip
import atexit
import random
from urllib.parse import unquote, urlparse, parse_qs
import concurrent.futures

# --- 1. 配置：确保 xray.exe 就在本脚本旁边 ---
XRAY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "xray.exe")

class UltimateAutoScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("节点真测工具 - 性能优化版")
        self.root.geometry("1000x750")

        if not os.path.exists(XRAY_PATH):
            messagebox.showwarning("找不到内核", f"请将 xray.exe 复制到:\n{os.path.dirname(XRAY_PATH)}")

        # --- UI 布局 ---
        tk.Label(root, text="粘贴节点链接 (支持 VLESS Reality / VMess)", font=('微软雅黑', 10)).pack(pady=5)
        self.input_area = tk.Text(root, height=12, font=('Consolas', 9))
        self.input_area.pack(padx=15, fill=tk.X)

        self.btn = tk.Button(root, text="🚀 开启深度并发检测", command=self.start_scan, 
                             bg="#2ecc71", fg="white", font=('微软雅黑', 11, 'bold'), height=2)
        self.btn.pack(pady=15)

        # 表格
        columns = ("status", "real_ip", "geo", "name", "original")
        self.tree = ttk.Treeview(root, columns=columns, show='headings')
        self.tree.heading("status", text="Google 状态")
        self.tree.heading("real_ip", text="真实落地 IP")
        self.tree.heading("geo", text="真实区域")
        self.tree.heading("name", text="备注名")
        
        self.tree.column("status", width=120, anchor="center")
        self.tree.column("real_ip", width=150)
        self.tree.column("geo", width=180)
        self.tree.column("name", width=350)
        self.tree.column("original", width=0, stretch=tk.NO)

        vsb = ttk.Scrollbar(root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(padx=15, fill=tk.BOTH, expand=True, side=tk.LEFT)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<Double-1>", self.on_double_click)
        self.running_processes = []
        atexit.register(self.cleanup)

    def parse_node(self, link):
        link = link.strip()
        try:
            if link.startswith('vless://'):
                u = urlparse(link)
                uuid, addr_port = u.netloc.split('@', 1)
                address, port = addr_port.rsplit(':', 1)
                query = {k: unquote(v[-1]) for k, v in parse_qs(u.query, keep_blank_values=True).items()}
                return {
                    "protocol": "vless", "addr": address, "port": int(port),
                    "uuid": uuid, "type": query.get('type', 'tcp'),
                    "path": query.get('path', '/'), "sni": query.get('sni', ''),
                    "security": query.get('security', 'none'), "flow": query.get('flow', ''),
                    "fp": query.get('fp', ''), "pbk": query.get('pbk', ''),
                    "sid": query.get('sid', ''), "spx": query.get('spx', ''),
                    "header_type": query.get('headerType', 'none'), "raw": link,
                    "name": unquote(u.fragment) if u.fragment else "未命名"
                }
            elif link.startswith('vmess://'):
                b64_str = link[8:]
                config = json.loads(base64.b64decode(b64_str + '=' * (-len(b64_str) % 4)).decode('utf-8'))
                return {
                    "protocol": "vmess", "addr": config['add'], "port": int(config['port']),
                    "uuid": config['id'], "type": config.get('net', 'tcp'),
                    "path": config.get('path', '/'), "sni": config.get('sni', ''),
                    "security": config.get('tls', 'none'), "raw": link,
                    "name": config.get('ps', '未命名')
                }
        except: return None



    def run_test(self, node, local_port):
        # 构建核心流设置
        stream_settings = {"network": node["type"], "security": node["security"]}

        if node["security"] == "tls":
            stream_settings["tlsSettings"] = {"serverName": node["sni"], "allowInsecure": True}
        elif node["security"] == "reality":
            stream_settings["realitySettings"] = {
                "serverName": node["sni"],
                "fingerprint": node.get("fp", "chrome"),
                "publicKey": node.get("pbk", "")
            }
            if node.get("sid"):
                stream_settings["realitySettings"]["shortId"] = node["sid"]
            if node.get("spx"):
                stream_settings["realitySettings"]["spiderX"] = node["spx"]

        if node["type"] == "ws":
            stream_settings["wsSettings"] = {"path": node["path"]}
        elif node["type"] == "tcp" and node.get("header_type") not in ["", "none"]:
            stream_settings["tcpSettings"] = {"header": {"type": node.get("header_type", "none")}}

        user = {"id": node["uuid"], "encryption": "none"}
        if node["protocol"] == "vless" and node.get("flow"):
            user["flow"] = node["flow"]

        config = {
            "inbounds": [{"port": local_port, "protocol": "socks", "settings": {"udp": True}}],
            "outbounds": [{
                "protocol": node["protocol"],
                "settings": {"vnext": [{"address": node["addr"], "port": node["port"],
                             "users": [user]}]},
                "streamSettings": stream_settings
            }]
        }

        config_file = os.path.abspath(f"tmp_{local_port}.json")
        with open(config_file, 'w') as f:
            json.dump(config, f)

        res = ("❌ 失败", "-", "无法连通", node["name"], node["raw"])
        proc = None
        try:
            proc = subprocess.Popen([XRAY_PATH, "-c", config_file],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, encoding='utf-8')
            self.running_processes.append(proc)

            time.sleep(4)

            exit_code = proc.poll()
            if exit_code is not None:
                _, stderr_output = proc.communicate(timeout=1)
                stderr_output = (stderr_output or "").strip().replace(chr(13), " ").replace(chr(10), " | ")
                short_error = stderr_output[:120] if stderr_output else f"xray 提前退出({exit_code})"
                return ("❌ Xray失败", "-", short_error, node["name"], node["raw"])

            proxies = {
                "http": f"socks5h://127.0.0.1:{local_port}",
                "https": f"socks5h://127.0.0.1:{local_port}"
            }

            status = "❌ Google失败"
            real_ip = "-"
            geo = "未获取IP"

            try:
                g = requests.get("https://www.google.com/generate_204", proxies=proxies, timeout=5)
                status = "✅ Google通" if g.status_code == 204 else f"❓ Google:{g.status_code}"
            except Exception as e:
                google_error = str(e).replace(chr(13), " ").replace(chr(10), " ")
                status = f"❌ Google失败:{google_error[:40]}"

            ip_errors = []

            try:
                ip_response = requests.get("https://api.ip.sb/geoip", proxies=proxies, timeout=8)
                ip_response.raise_for_status()
                ip_data = ip_response.json()
                real_ip = ip_data.get("ip", "-")
                country = ip_data.get("country") or ip_data.get("country_code") or "未知国家"
                region = ip_data.get("region") or ip_data.get("city") or "未知地区"
                geo = f"{country}·{region}"
            except Exception as e:
                ip_errors.append(f"ip.sb:{str(e).replace(chr(13), ' ').replace(chr(10), ' ')[:30]}")
                try:
                    ip_response = requests.get("http://ip-api.com/json/?lang=zh-CN", proxies=proxies, timeout=8)
                    ip_response.raise_for_status()
                    ip_data = ip_response.json()
                    if ip_data.get("status") == "success":
                        real_ip = ip_data.get("query", "-")
                        geo = f"{ip_data.get('country')}·{ip_data.get('regionName')}"
                    else:
                        api_message = str(ip_data.get("message", "ip-api 返回失败")).replace(chr(13), " ").replace(chr(10), " ")
                        ip_errors.append(f"ip-api:{api_message[:30]}")
                        geo = "IP查询失败"
                except Exception as e:
                    ip_errors.append(f"ip-api:{str(e).replace(chr(13), ' ').replace(chr(10), ' ')[:30]}")
                    geo = "IP查询失败:" + " | ".join(ip_errors)[:80]

            res = (status, real_ip, geo, node["name"], node["raw"])
        except Exception as e:
            error_text = str(e).replace(chr(13), " ").replace(chr(10), " ")
            res = ("❌ 错误", "-", error_text[:120], node["name"], node["raw"])
        finally:
            if proc:
                try:
                    proc.kill()
                except:
                    pass
            if os.path.exists(config_file):
                try:
                    os.remove(config_file)
                except:
                    pass

        return res

    def start_scan(self):
        text = self.input_area.get(1.0, tk.END).strip()
        if not text: return

        # 1. 自动清理之前的残留进程
        self.cleanup()
        
        for item in self.tree.get_children(): self.tree.delete(item)
        self.btn.config(state=tk.DISABLED, text="全自动扫描中...")

        lines = text.split('\n')
        nodes = [n for n in (self.parse_node(l) for l in lines) if n]
        
        # 使用随机起始端口段，避免冲突
        base_port = random.randint(30000, 45000)

        def worker(idx_node):
            return self.run_test(idx_node[1], base_port + idx_node[0])

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            for result in executor.map(worker, enumerate(nodes)):
                self.tree.insert("", tk.END, values=result)
                self.root.update()

        self.btn.config(state=tk.NORMAL, text="🚀 开启深度并发检测")
        messagebox.showinfo("完成", f"检测了 {len(nodes)} 个节点。")

    def on_double_click(self, event):
        item = self.tree.selection()[0]
        raw_link = self.tree.item(item, "values")[4]
        pyperclip.copy(raw_link)
        messagebox.showinfo("复制成功", "节点链接已复制。")

    def cleanup(self):
        for p in self.running_processes:
                try: p.kill()
                except: pass
        self.running_processes = []

    def on_closing(self):
        self.cleanup()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = UltimateAutoScanner(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
