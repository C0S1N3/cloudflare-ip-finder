import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import argparse
import fnmatch
import socket
import ssl
import sys
import time
import json
import csv
import ipaddress
import threading
import zipfile
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import subprocess
import platform
import dns.resolver
from packaging import version
import winreg
import urllib3
import random

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG_PATH = Path.home() / '.cf_ip_scanner_config.json'
HISTORY_PATH = Path.home() / '.cf_ip_scanner_history.json'

class ConfigManager:
    DEFAULT_CONFIG = {
        'ip_type': 'IPv4',
        'test_count': 500,
        'max_threads': 100,
        'timeout': 3,
        'history_limit': 30,
        'proxy_settings': {
            'enable': False,
            'port': 1080,
            'protocol': 'socks5'
        },
        'cloudflare_domains': [
            'speed.cloudflare.com',
            'cloudflare.com',
            'www.cloudflare.com',
            'developers.cloudflare.com',
            'community.cloudflare.com'
        ],
        'test_retries': 3,
        'ip_persistent': True,
        'ip_file_path': str(Path.home() / '.cf_ip_list.txt'),
    }

    @classmethod
    def load_config(cls):
        """加载配置"""
        try:
            if CONFIG_PATH.exists():
                with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    default_domains = cls.DEFAULT_CONFIG.get('cloudflare_domains', [])
                    config_domains = config.get('cloudflare_domains', [])
                    config['cloudflare_domains'] = config_domains if config_domains else default_domains
                    return {**cls.DEFAULT_CONFIG, **config}
            return cls.DEFAULT_CONFIG
        except FileNotFoundError:
            return cls.DEFAULT_CONFIG
        except json.JSONDecodeError:
            print("Warning: Config file corrupted, loading default config.")
            return cls.DEFAULT_CONFIG

    @classmethod
    def save_config(cls, config):
        """保存配置"""
        try:
            with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving config: {e}")

class NetworkDiagnostics:
    @staticmethod
    def traceroute(host):
        """路由追踪"""
        os_type = platform.system()
        command = ['tracert', '-d', host] if os_type == 'Windows' else ['traceroute', host]

        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            output, error = proc.communicate()
            return output if not error else f"Error: {error}"
        except Exception as e:
            return str(e)

    @staticmethod
    def dns_lookup(host, dns_server=None):
        """DNS 解析"""
        try:
            resolver = dns.resolver.Resolver()
            if dns_server:
                resolver.nameservers = [dns_server]

            answers = resolver.resolve(host, 'A')
            return [str(r) for r in answers]
        except Exception as e:
            return f"DNS lookup failed: {e}"

    @staticmethod
    def tcp_ping(host, port, timeout=3):
        """TCP Ping"""
        try:
            start = time.time()
            with socket.create_connection((host, port), timeout=timeout):
                latency = (time.time() - start) * 1000
                return f"Connected in {latency:.2f}ms"
        except socket.error as e:
            return f"Connection failed: {e}"

class HistoryManager:
    """历史记录管理"""
    def __init__(self):
        self.config = ConfigManager.load_config()
        self.history_file = HISTORY_PATH
        self.history = self._load_history()

    def _load_history(self):
        """加载历史记录"""
        try:
            if self.history_file.exists():
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            return []
        except Exception as e:
            print(f"Load history failed: {e}")
            return []

    def save_history(self):
        """保存历史记录"""
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(self.history[-self.config['history_limit']:], f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Save history failed: {e}")

    def add_record(self, record):
        """添加记录"""
        self.history.append({
            'timestamp': time.time(),
            'data': record
        })
        self.save_history()

    def get_comparison_data(self, days=7):
        """获取对比数据"""
        cutoff = time.time() - days * 86400
        return [r for r in self.history if r['timestamp'] > cutoff]

class SystemProxy:
    """系统代理配置"""
    PROXY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

    @classmethod
    def configure_proxy(cls, enable=True, server='127.0.0.1:1080', bypass=''):
        """配置系统代理"""
        if platform.system() != 'Windows':
            print("System proxy configuration is only supported on Windows.")
            return False
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.PROXY_PATH, 0, winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 1 if enable else 0)
                winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, server)
                winreg.SetValueEx(key, 'ProxyOverride', 0, winreg.REG_SZ, bypass)
            return True
        except Exception as e:
            print(f"Proxy config failed: {e}")
            return False

class IPManager:
    """IP 地址管理"""
    def __init__(self):
        self.config = ConfigManager.load_config()
        self.cidr_history = set()

    def generate_and_save_ips(self, cidrs, ip_type='IPv4'):
        """增量生成并存储IP地址"""
        new_ips = set()

        if Path(self.config['ip_file_path']).exists():
            with open(self.config['ip_file_path'], 'r') as f:
                for line in f:
                    if '/' in line:
                        self.cidr_history.add(line.strip())

        for cidr in cidrs:
            if cidr not in self.cidr_history:
                network = ipaddress.ip_network(cidr)
                new_ips.update(str(host) for host in network.hosts())

        if new_ips:
            with open(self.config['ip_file_path'], 'a') as f:
                f.write('\n'.join(new_ips) + '\n')
            self.cidr_history.update(cidrs)

    def load_ips(self):
        """从文件加载IP列表"""
        if Path(self.config['ip_file_path']).exists():
            with open(self.config['ip_file_path'], 'r') as f:
                return [line.strip() for line in f if '.' in line]
        return []

class CloudFlareIPScanner:
    """Cloudflare IP 扫描器"""
    def __init__(self):
        self.ip_manager = IPManager()
        self.cf_ip_ranges = {
            'IPv4': [
                '173.245.48.0/20',
                '103.21.244.0/22',
                '103.22.200.0/22',
                '103.31.4.0/22',
                '141.101.64.0/18',
                '108.162.192.0/18',
                '190.93.240.0/20',
                '188.114.96.0/20',
                '197.234.240.0/22',
                '198.41.128.0/17',
                '162.158.0.0/15',
                '104.16.0.0/13',
                '104.24.0.0/14',
                '172.64.0.0/13',
                '131.0.72.0/22'
            ]
        }
        self.config = ConfigManager.load_config()
        self.load_ip_ranges()

    def load_ip_ranges(self):
        """加载IP范围"""
        try:
            self._fetch_latest_ips()
        except Exception as e:
            print(f"IP update failed, using default embedded ranges: {e}")

    def _fetch_latest_ips(self):
        """获取最新的IP范围"""
        ipv4_url = "https://www.cloudflare.com/ips-v4"

        try:
            ipv4_ips = requests.get(ipv4_url, timeout=10).text.splitlines()

            self.cf_ip_ranges['IPv4'] = [ip for ip in ipv4_ips if ip]
            print("Cloudflare IPv4 ranges updated successfully from website.")
        except requests.exceptions.RequestException as e:
            print(f"Failed to update Cloudflare IPv4 ranges from website, using embedded ranges: {e}")

    def generate_ips(self, ip_type='IPv4', count=500):
        """生成IP地址（支持持久化）"""
        if self.config['ip_persistent']:
            if not Path(self.config['ip_file_path']).exists():
                self.ip_manager.generate_and_save_ips(self.cf_ip_ranges['IPv4'])
            all_ips = self.ip_manager.load_ips()
            if not all_ips:
                print("Warning: No IPs loaded from persistent file, falling back to CIDR range generation.")
                return self._generate_ips_from_cidr(ip_type, count)
            return random.sample(all_ips, min(count, len(all_ips)))
        else:
            return self._generate_ips_from_cidr(ip_type, count)

    def _generate_ips_from_cidr(self, ip_type='IPv4', count=500):
        """从 CIDR 生成 IP"""
        from random import choice
        ips = []
        if ip_type in self.cf_ip_ranges:
            for cidr in self.cf_ip_ranges[ip_type]:
                network = ipaddress.ip_network(cidr)
                for _ in range(max(1, count//len(self.cf_ip_ranges[ip_type]))):
                    ip = str(network[choice(range(1, network.num_addresses))])
                    ips.append(ip)
        return list(set(ips))[:count]

    def test_latency(self, ip, port=443, timeout=3, proxy_config=None):
        """改进后的测速方法（支持重试）"""
        result = {'ip': ip, 'tcp': [], 'http': [], 'https': []}

        for _ in range(self.config['test_retries']):
            try:
                start = time.perf_counter()
                with socket.create_connection((ip, port), timeout=timeout, source_address=('0.0.0.0', 0)):
                    latency = (time.perf_counter() - start) * 1000
                    result['tcp'].append(latency)
                break
            except:
                continue

        for _ in range(self.config['test_retries']):
            try:
                start = time.perf_counter()
                requests.get(f'http://{ip}',
                    headers={'Host': 'speed.cloudflare.com'},
                    timeout=timeout,
                    proxies=self._get_proxies(proxy_config)
                )
                result['http'].append((time.perf_counter() - start) * 1000)
                break
            except:
                continue

        for _ in range(self.config['test_retries']):
            try:
                start = time.perf_counter()
                requests.get(f'https://{ip}',
                    headers={'Host': 'speed.cloudflare.com'},
                    timeout=timeout,
                    verify=False,
                    proxies=self._get_proxies(proxy_config)
                )
                result['https'].append((time.perf_counter() - start) * 1000)
                break
            except:
                continue

        result['tcp_avg'] = self._calc_avg(result['tcp'])
        result['http_avg'] = self._calc_avg(result['http'])
        result['https_avg'] = self._calc_avg(result['https'])
        return result

    def _calc_avg(self, values):
        """计算平均值"""
        return sum(values)/len(values) if values else None

    def _get_proxies(self, proxy_config):
        """代理配置方法抽取"""
        if proxy_config and proxy_config['enable']:
            protocol = proxy_config['protocol']
            server = f"127.0.0.1:{proxy_config['port']}"
            if protocol == 'socks5':
                return {'http': f'socks5://{server}', 'https': f'socks5://{server}'}
            elif protocol == 'http':
                return {'http': f'http://{server}', 'https': f'http://{server}'}
        return None

    def analyze_results(self, results):
        """结果分析及评分"""
        valid_results = [r for r in results if r['https_avg']]
        if not valid_results:
            return []

        min_latency = min(r['https_avg'] for r in valid_results)
        for r in valid_results:
            score = (min_latency / r['https_avg']) * 0.6
            score += 0.4 * (1 - min(r['https_avg'], 1000)/1000)
            r['score'] = round(score, 2)

        return sorted(valid_results, key=lambda x: x['score'], reverse=True)

class Exporter:
    """导出器"""
    @staticmethod
    def export_hosts(results, path):
        """导出 Hosts 文件"""
        config = ConfigManager.load_config()
        domains = config['cloudflare_domains']
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write("# CloudFlare Optimized IPs\n")
                for result in results:
                    for domain in domains:
                        f.write(f"{result['ip']}    {domain}\n")
            return True
        except Exception as e:
            print(f"Export Hosts failed: {e}")
            return False

    @staticmethod
    def export_json(results, path):
        """导出 JSON 文件"""
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump({
                    'generated': time.time(),
                    'results': results
                }, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Export JSON failed: {e}")
            return False

    @staticmethod
    def export_csv(results, path):
        """导出 CSV 文件"""
        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                if results:
                    writer = csv.DictWriter(f, fieldnames=results[0].keys())
                    writer.writeheader()
                    writer.writerows(results)
            return True
        except Exception as e:
            print(f"Export CSV failed: {e}")
            return False

class BGACNTargetScanner:
    """Cloudflare 站点优选引擎（target 可换任意托管在 Cloudflare 的网站，默认 bgacn.com）

    与通用模式的区别：
      * 直接以目标站 SNI 做 TLS 握手测速（国内被限速掐的正是带 SNI 的握手这一步），
        而不是拿 speed.cloudflare.com 等无关域名估延迟；
      * 校验证书覆盖目标域 + HTTP 200，确认该 IP 真的在服务目标站；
      * 每个 IP 多次采样，按稳定性（命中率）排序，单次最快往往最抖。
    """

    HOSTS_TAG = "cf-ip-finder:bgacn"

    # Cloudflare 官方 IPv4 段（内嵌，扫描不依赖在线拉取）
    CF_RANGES = [
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
        '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    ]

    def __init__(self, target='bgacn.com', reps=3, timeout=3.0):
        self.target = target
        self.reps = reps
        self.timeout = timeout

    def host_names(self):
        """目标域 + 对应 www 变体"""
        if self.target.startswith('www.'):
            return [self.target, self.target[4:]]
        return [self.target, 'www.' + self.target]

    def sample_ips(self, count):
        """从 CF 网段均匀采样 count 个 IP"""
        per = max(1, count // len(self.CF_RANGES))
        out, seen = [], set()
        for cidr in self.CF_RANGES:
            net = ipaddress.ip_network(cidr)
            base = int(net.network_address)
            span = net.num_addresses - 2  # 排除网络地址/广播地址
            for offset in random.sample(range(1, span + 1), min(per, span)):
                s = str(ipaddress.IPv4Address(base + offset))
                if s not in seen:
                    seen.add(s)
                    out.append(s)
        random.shuffle(out)
        return out[:count]

    @staticmethod
    def _cert_matches(host, names):
        """简易通配符匹配：*.example.com 或 example.com"""
        for n in names:
            if n == host or fnmatch.fnmatch(host, n):
                return True
        return False

    def _probe_once(self, ip):
        """单次 TLS 握手测速，返回握手耗时（秒）；证书不符/被掐/非 200 返回 None"""
        try:
            t0 = time.perf_counter()
            raw = socket.create_connection((ip, 443), timeout=self.timeout)
            raw.settimeout(self.timeout)
            ctx = ssl.create_default_context()
            try:
                ss = ctx.wrap_socket(raw, server_hostname=self.target)
            except ssl.SSLError:
                raw.close()
                return None
            tls = time.perf_counter() - t0
            # 确认证书确实覆盖目标域（防止连到别的 CF 客户）
            cert = ss.getpeercert()
            names = [v for t, v in cert.get('subjectAltName', ()) if t == 'DNS']
            if not self._cert_matches(self.target, names):
                ss.close()
                return None
            # 确认真的返回 200
            ss.sendall(
                f"HEAD / HTTP/1.1\r\nHost: {self.target}\r\nConnection: close\r\n"
                f"User-Agent: cf-ip-scanner\r\n\r\n".encode()
            )
            head = ss.recv(200)
            ss.close()
            if b"HTTP/" in head:
                try:
                    code = int(head.split()[1])
                except Exception:
                    return None
                return tls if code == 200 else None
            return None
        except Exception:
            return None

    def probe_ip(self, ip):
        """对单个 IP 做 reps 次握手，返回稳定性统计"""
        times = []
        for _ in range(self.reps):
            t = self._probe_once(ip)
            if t is not None:
                times.append(t)
            time.sleep(0.05)
        if not times:
            return {'ip': ip, 'ok': False, 'hits': 0, 'reps': self.reps}
        return {
            'ip': ip, 'ok': True, 'hits': len(times), 'reps': self.reps,
            'rate': len(times) / self.reps,
            'avg': sum(times) / len(times),
            'worst': max(times), 'best': min(times),
        }

    def scan(self, count, workers=120, log=print, cancel=None):
        """扫描并按稳定性排序返回可用 IP（命中率降序 → 平均握手升序 → 最差握手升序）"""
        ips = self.sample_ips(count)
        log(f"目标 {self.target} | 扫描 {len(ips)} 个 Cloudflare IP | 每个 {self.reps} 次握手 ...")
        results, done = [], 0
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = [ex.submit(self.probe_ip, ip) for ip in ips]
            for fut in as_completed(futures):
                if cancel and cancel():
                    for pending in futures:
                        pending.cancel()
                    break
                results.append(fut.result())
                done += 1
                if done % 100 == 0:
                    okc = sum(1 for r in results if r['ok'])
                    log(f"进度 {done}/{len(ips)}  可用 {okc}")
        good = [r for r in results if r['ok']]
        good.sort(key=lambda r: (-r['rate'], r['avg'], r['worst']))
        return good

    # ---------------- hosts 写入 ----------------
    @staticmethod
    def _hosts_path():
        if platform.system() == 'Windows':
            return r"C:\Windows\System32\drivers\etc\hosts"
        return "/etc/hosts"

    def apply_hosts(self, ip):
        """把最优 IP 写入 hosts（目标域的旧映射一并清理），需管理员权限"""
        names = self.host_names()
        keys = set(names)
        path = self._hosts_path()
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                data = f.read()
            out = []
            for line in data.splitlines():
                s = line.strip()
                if not s or s.startswith('#'):
                    if self.HOSTS_TAG in line:
                        continue
                    out.append(line)
                    continue
                fields = s.split()
                # 带本工具标记的行、以及映射到目标域的旧映射都清掉，避免重复映射
                if self.HOSTS_TAG in line or (len(fields) >= 2 and keys.intersection(fields[1:])):
                    continue
                out.append(line)
            block = [f"# {self.HOSTS_TAG} begin {self.target} -> {ip}"]
            for n in names:
                block.append(f"{ip}    {n}    # {self.HOSTS_TAG}")
            block.append(f"# {self.HOSTS_TAG} end")
            with open(path, 'w', encoding='utf-8', errors='replace') as f:
                f.write("\n".join(out).rstrip() + "\n\n" + "\n".join(block) + "\n")
        except PermissionError:
            return False, "无权限读写 hosts，请以管理员身份运行。"
        except OSError as e:
            return False, f"hosts 操作失败: {e}"
        return True, "已写入 hosts（旧映射已清除）:\n" + "\n".join(block)

    def remove_hosts(self):
        """只清理本工具写入的条目（按注释标记识别），不碰用户自己的 hosts 内容"""
        path = self._hosts_path()
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                data = f.read()
            lines = data.splitlines()
            out = [line for line in lines if self.HOSTS_TAG not in line]
            if len(out) == len(lines):
                return False, "hosts 里没有本工具写入的条目。"
            with open(path, 'w', encoding='utf-8', errors='replace') as f:
                f.write("\n".join(out).rstrip() + "\n")
        except PermissionError:
            return False, "无权限写 hosts，请以管理员身份运行。"
        except OSError as e:
            return False, f"hosts 操作失败: {e}"
        return True, "已从 hosts 移除本工具写入的条目。"


class HistoryWindow(tk.Toplevel):
    """历史记录窗口"""
    def __init__(self, parent):
        super().__init__(parent)
        self.title("测试历史记录")
        self.geometry("600x400")

        columns = ('timestamp', 'best_ip', 'avg_latency')
        self.tree = ttk.Treeview(self, columns=columns, show='headings')

        self.tree.heading('timestamp', text="测试时间")
        self.tree.heading('best_ip', text="最佳IP")
        self.tree.heading('avg_latency', text="平均延迟 (HTTPS)")

        self.tree.pack(fill=tk.BOTH, expand=True)
        self.load_data()

    def load_data(self):
        """加载数据"""
        history_manager = HistoryManager()
        history = history_manager.history
        for record in reversed(history):
            data = record['data']
            if data:
                avg_latency = sum(r['https_avg'] for r in data) / len(data) if data else 0
                best_ip = data[0]['ip'] if data else "N/A"
                self.tree.insert('', 'end', values=(
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(record['timestamp'])),
                    best_ip,
                    f"{avg_latency:.1f}ms"
                ))
            else:
                self.tree.insert('', 'end', values=(
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(record['timestamp'])),
                    "No valid results",
                    "N/A"
                ))

class DiagnosticsWindow(tk.Toplevel):
    """网络诊断工具窗口"""
    def __init__(self, parent):
        super().__init__(parent)
        self.title("网络诊断工具")
        self.geometry("600x400")

        ttk.Label(self, text="目标地址:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.target = ttk.Entry(self, width=40)
        self.target.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
        self.target.insert(0, "speed.cloudflare.com")

        ttk.Button(self, text="路由追踪", command=self.run_traceroute).grid(row=1, column=0, padx=5, pady=5, sticky='ew')
        ttk.Button(self, text="DNS解析", command=self.run_dns_lookup).grid(row=1, column=1, padx=5, pady=5, sticky='ew')

        self.output = tk.Text(self, wrap=tk.WORD, height=10)
        self.output.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky='nsew')
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=1)

    def run_traceroute(self):
        """运行路由追踪"""
        host = self.target.get()
        self.output.delete(1.0, tk.END)
        self.output.insert(tk.END, "正在进行路由追踪...\n")
        threading.Thread(target=self._do_traceroute, args=(host,)).start()

    def _do_traceroute(self, host):
        """执行路由追踪"""
        result = NetworkDiagnostics.traceroute(host)
        self.output.delete(1.0, tk.END)
        self.output.insert(tk.END, result)

    def run_dns_lookup(self):
        """运行 DNS 解析"""
        host = self.target.get()
        self.output.delete(1.0, tk.END)
        self.output.insert(tk.END, "正在进行DNS解析...\n")
        threading.Thread(target=self._do_dns_lookup, args=(host,)).start()

    def _do_dns_lookup(self, host):
        """执行 DNS 解析"""
        result = NetworkDiagnostics.dns_lookup(host)
        self.output.delete(1.0, tk.END)
        self.output.insert(tk.END, str(result))

class ConfigWindow(tk.Toplevel):
    """配置窗口"""
    def __init__(self, parent, app):
        super().__init__(parent)
        self.title("配置")
        self.geometry("450x450")
        self.app = app
        self.config_manager = ConfigManager()
        self.current_config = self.config_manager.load_config()

        ttk.Label(self, text="IP类型:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.ip_type = ttk.Combobox(self, values=['IPv4'], width=8)
        self.ip_type.set(self.current_config['ip_type'])
        self.ip_type.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
        self.ip_type.config(state='readonly')

        ttk.Label(self, text="测试数量:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.test_count = ttk.Spinbox(self, from_=100, to=5000, width=7)
        self.test_count.set(self.current_config['test_count'])
        self.test_count.grid(row=1, column=1, padx=5, pady=5, sticky='ew')

        ttk.Label(self, text="最大线程:").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        self.max_threads = ttk.Spinbox(self, from_=10, to=200, width=7)
        self.max_threads.set(self.current_config['max_threads'])
        self.max_threads.grid(row=2, column=1, padx=5, pady=5, sticky='ew')

        ttk.Label(self, text="超时时间 (秒):").grid(row=3, column=0, padx=5, pady=5, sticky='w')
        self.timeout = ttk.Spinbox(self, from_=1, to=10, width=3)
        self.timeout.set(self.current_config['timeout'])
        self.timeout.grid(row=3, column=1, padx=5, pady=5, sticky='ew')

        ttk.Label(self, text="测试重试次数:").grid(row=4, column=0, padx=5, pady=5, sticky='w')
        self.test_retries = ttk.Spinbox(self, from_=1, to=10, width=3)
        self.test_retries.set(self.current_config['test_retries'])
        self.test_retries.grid(row=4, column=1, padx=5, pady=5, sticky='ew')

        self.ip_persistent_var = tk.BooleanVar(value=self.current_config['ip_persistent'])
        ttk.Checkbutton(self, text="启用IP持久化", variable=self.ip_persistent_var).grid(row=5, column=0, columnspan=2, padx=5, pady=5, sticky='w')

        ttk.Label(self, text="Cloudflare 域名列表 (每行一个):").grid(row=6, column=0, padx=5, pady=5, sticky='nw')
        self.domains_text = tk.Text(self, height=5, width=30)
        self.domains_text.grid(row=6, column=1, padx=5, pady=5, sticky='ew')
        self.domains_text.insert(tk.END, "\n".join(self.current_config['cloudflare_domains']))

        ttk.Button(self, text="保存配置", command=self.save_config).grid(row=7, column=0, columnspan=2, padx=5, pady=10)

        self.grid_columnconfigure(1, weight=1)

    def save_config(self):
        """保存配置"""
        self.current_config['ip_type'] = self.ip_type.get()
        self.current_config['test_count'] = int(self.test_count.get())
        self.current_config['max_threads'] = int(self.max_threads.get())
        self.current_config['timeout'] = int(self.timeout.get())
        self.current_config['test_retries'] = int(self.test_retries.get())
        self.current_config['ip_persistent'] = self.ip_persistent_var.get()
        self.current_config['cloudflare_domains'] = [domain.strip() for domain in self.domains_text.get("1.0", tk.END).strip().splitlines() if domain.strip()]

        ConfigManager.save_config(self.current_config)
        self.app.scanner.config = self.current_config
        self.destroy()
        messagebox.showinfo("配置已保存", "配置已成功保存。")

class BGACNWindow(tk.Toplevel):
    """Cloudflare 网站优选窗口（目标域名可改，默认 bgacn.com）"""

    def __init__(self, parent):
        super().__init__(parent)
        self.title("Cloudflare 网站优选 IP")
        self.geometry("660x520")
        self.running = False
        self.results = []

        row1 = ttk.Frame(self)
        row1.pack(pady=8, fill=tk.X, padx=10)
        ttk.Label(row1, text="目标域名:").grid(row=0, column=0, padx=5)
        self.target_entry = ttk.Entry(row1, width=16)
        self.target_entry.insert(0, "bgacn.com")  # 默认 bgacn.com，可改成任意 CF 网站
        self.target_entry.grid(row=0, column=1, padx=5)

        ttk.Label(row1, text="测试数量:").grid(row=0, column=2, padx=5)
        self.count_spin = ttk.Spinbox(row1, from_=50, to=5000, width=6)
        self.count_spin.set(400)
        self.count_spin.grid(row=0, column=3, padx=5)

        ttk.Label(row1, text="握手次数:").grid(row=0, column=4, padx=5)
        self.reps_spin = ttk.Spinbox(row1, from_=1, to=10, width=3)
        self.reps_spin.set(3)
        self.reps_spin.grid(row=0, column=5, padx=5)

        ttk.Label(row1, text="超时(秒):").grid(row=0, column=6, padx=5)
        self.timeout_spin = ttk.Spinbox(row1, from_=1, to=10, width=3)
        self.timeout_spin.set(3)
        self.timeout_spin.grid(row=0, column=7, padx=5)

        row2 = ttk.Frame(self)
        row2.pack(pady=4, fill=tk.X, padx=10)
        self.start_btn = ttk.Button(row2, text="开始优选", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = ttk.Button(row2, text="停止", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        self.apply_btn = ttk.Button(row2, text="写入Hosts", command=self.apply_hosts)
        self.apply_btn.pack(side=tk.LEFT, padx=5)
        self.remove_btn = ttk.Button(row2, text="从Hosts移除", command=self.remove_hosts)
        self.remove_btn.pack(side=tk.LEFT, padx=5)
        self.yaml_btn = ttk.Button(row2, text="生成YAML", command=self.export_yaml)
        self.yaml_btn.pack(side=tk.LEFT, padx=5)
        self.merge_btn = ttk.Button(row2, text="生成Merge", command=self.export_merge)
        self.merge_btn.pack(side=tk.LEFT, padx=5)
        self.magisk_btn = ttk.Button(row2, text="导出Magisk", command=self.export_magisk)
        self.magisk_btn.pack(side=tk.LEFT, padx=5)

        columns = ('ip', 'hits', 'avg', 'worst')
        self.tree = ttk.Treeview(self, columns=columns, show='headings', selectmode='browse')
        self.tree.heading('ip', text='IP地址')
        self.tree.heading('hits', text='命中')
        self.tree.heading('avg', text='平均握手(ms)')
        self.tree.heading('worst', text='最差握手(ms)')
        self.tree.column('hits', anchor='center', width=70)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)

        self.status = ttk.Label(self, text="目标域名可改成任何托管在 Cloudflare 的网站 | 以目标站 SNI 测 TLS 握手，按稳定性排序（命中率优先）", relief=tk.SUNKEN, anchor='w')
        self.status.pack(fill=tk.X, side=tk.BOTTOM)

    def start_scan(self):
        if self.running:
            return
        self.running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.tree.delete(*self.tree.get_children())
        self.results = []
        threading.Thread(target=self._run_scan, daemon=True).start()

    def stop_scan(self):
        self.running = False
        self.status.config(text="停止中...")

    def _run_scan(self):
        target = self.target_entry.get().strip() or 'bgacn.com'
        scanner = BGACNTargetScanner(target, int(self.reps_spin.get()), float(self.timeout_spin.get()))
        count = int(self.count_spin.get())
        self._log(f"目标 {target} | 扫描 {count} 个 Cloudflare IP ...")
        try:
            good = scanner.scan(count, workers=120, log=self._log, cancel=lambda: not self.running)
        except Exception as e:
            self.after(0, lambda: self._finish_scan([], f"扫描出错: {e}"))
            return
        self.after(0, self._finish_scan, good, None)

    def _log(self, msg):
        self.after(0, lambda: self.status.config(text=msg))

    def _finish_scan(self, good, error):
        self.running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.results = good
        for r in good:
            self.tree.insert('', 'end', values=(
                r['ip'],
                f"{r['hits']}/{r['reps']}",
                f"{r['avg'] * 1000:.0f}",
                f"{r['worst'] * 1000:.0f}",
            ))
        if error:
            self.status.config(text=error)
        elif good:
            self.status.config(text=f"完成 | 可用 {len(good)} 个 IP，最稳: {good[0]['ip']}（命中 {good[0]['hits']}/{good[0]['reps']}）")
        else:
            self.status.config(text="没有找到可用 IP，可增大测试数量或超时重试。")

    def _scanner(self):
        target = self.target_entry.get().strip() or 'bgacn.com'
        return BGACNTargetScanner(target)

    def apply_hosts(self):
        if not self.results:
            messagebox.showinfo("写入Hosts", "请先运行优选。")
            return
        sel = self.tree.selection()
        ip = self.tree.item(sel[0], 'values')[0] if sel else self.results[0]['ip']
        ok, msg = self._scanner().apply_hosts(ip)
        (messagebox.showinfo if ok else messagebox.showerror)("写入Hosts", msg)

    def remove_hosts(self):
        ok, msg = self._scanner().remove_hosts()
        messagebox.showinfo("从Hosts移除", msg)

    def _export(self, kind):
        if not self.results:
            messagebox.showinfo("导出", "请先运行优选。")
            return
        sel = self.tree.selection()
        ip = self.tree.item(sel[0], 'values')[0] if sel else self.results[0]['ip']
        target = self.target_entry.get().strip() or 'bgacn.com'
        is_yaml = kind == "yaml"
        is_magisk = kind == "magisk"
        if is_magisk:
            title = "生成 Magisk 模块（systemless hosts，需 root）"
            initial = f"{target}-magisk.zip"
            types = [("ZIP", "*.zip"), ("所有文件", "*.*")]
        elif is_yaml:
            title = "生成 Clash 独立配置"
            initial = f"{target}-clash.yaml"
            types = [("YAML", "*.yaml *.yml"), ("所有文件", "*.*")]
        else:
            title = "生成 Clash Verge 覆写合并片段"
            initial = f"{target}-merge.yaml"
            types = [("YAML", "*.yaml *.yml"), ("所有文件", "*.*")]
        path = filedialog.asksaveasfilename(
            title=title, defaultextension=".zip" if is_magisk else ".yaml",
            initialfile=initial, filetypes=types,
        )
        if not path:
            return
        try:
            if is_magisk:
                ok, msg = magisk_module_zip(path, ip, target)
            else:
                text = clash_yaml_text(ip, target) if is_yaml else clash_merge_text(ip, target)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text)
                ok, msg = True, f"已生成 -> {path}（{target} -> {ip}）"
        except OSError as e:
            ok, msg = False, f"写入失败: {e}"
        (messagebox.showinfo if ok else messagebox.showerror)("导出", msg)
        self.status.config(text=msg.splitlines()[0])

    def export_yaml(self):
        """生成 Clash 独立配置（纯直连，无需订阅）。"""
        self._export("yaml")

    def export_merge(self):
        """生成 Clash Verge 覆写合并片段（挂到订阅上用）。"""
        self._export("merge")

    def export_magisk(self):
        """生成 Magisk 模块 zip（root 手机刷入，免 Clash）。"""
        self._export("magisk")


class Application(tk.Tk):
    """主应用程序类"""
    def __init__(self):
        super().__init__()
        self.scanner = CloudFlareIPScanner()
        self.history_manager = HistoryManager()
        self.app_config = self.scanner.config
        self.running = False
        self.results = []
        self.version = "1.4.0"
        self.init_ui()
        self.load_history()

    def init_ui(self):
        """初始化用户界面"""
        self.title(f"CloudFlare IP优选工具 v{self.version}")
        self.geometry("800x600")

        self.add_menu()

        control_frame = ttk.Frame(self)
        control_frame.pack(pady=10, fill=tk.X)

        ttk.Label(control_frame, text="IP类型:").grid(row=0, column=0, padx=5, pady=5)
        self.ip_type = ttk.Combobox(control_frame, values=['IPv4'], width=8)
        self.ip_type.set(self.app_config['ip_type'])
        self.ip_type.grid(row=0, column=1, padx=5, pady=5)
        self.ip_type.config(state='readonly')

        ttk.Label(control_frame, text="测试数量:").grid(row=0, column=2, padx=5, pady=5)
        self.test_count = ttk.Spinbox(control_frame, from_=100, to=5000, width=7)
        self.test_count.delete(0, 'end')
        self.test_count.insert(0, str(self.app_config['test_count']))
        self.test_count.grid(row=0, column=3, padx=5, pady=5)

        self.start_btn = ttk.Button(control_frame, text="开始测试", command=self.start_scan)
        self.start_btn.grid(row=0, column=4, padx=10, pady=5)

        self.stop_btn = ttk.Button(control_frame, text="停止测试", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=5, padx=10, pady=5)

        self.apply_hosts_btn = ttk.Button(control_frame, text="应用到Hosts", command=self.apply_hosts)
        self.apply_hosts_btn.grid(row=0, column=6, padx=10, pady=5)

        self.bgacn_btn = ttk.Button(control_frame, text="CF 网站优选", command=self.open_bgacn)
        self.bgacn_btn.grid(row=0, column=7, padx=10, pady=5)

        columns = ('ip', 'tcp', 'http', 'https', 'score')
        self.tree = ttk.Treeview(self, columns=columns, show='headings', selectmode='extended')

        self.tree.heading('ip', text='IP地址')
        self.tree.heading('tcp', text='TCP延迟(ms)')
        self.tree.heading('http', text='HTTP延迟(ms)')
        self.tree.heading('https', text='HTTPS延迟(ms)')
        self.tree.heading('score', text='综合评分',
                           command=lambda: messagebox.showinfo("评分标准", "综合评分 = (最低延迟 / 当前IP延迟) * 0.6 + (1 - min(当前IP延迟, 1000ms) / 1000ms) * 0.4\n\n评分越高，IP 质量越好。\n主要考虑 HTTPS 延迟，并对延迟较低的 IP 给予更高权重。"))
        self.tree.column('score', anchor='center')

        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.status_frame = ttk.Frame(self)
        self.status_frame.pack(fill=tk.X, side=tk.BOTTOM)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.status_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(side=tk.RIGHT, fill=tk.X, padx=5, pady=2, expand=True)

        self.status = ttk.Label(self.status_frame, text="就绪", relief=tk.SUNKEN, anchor='w')
        self.status.pack(fill=tk.X)

        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="导出到Hosts", command=self.export_hosts)
        self.menu.add_command(label="导出为JSON", command=self.export_json)
        self.menu.add_command(label="导出为CSV", command=self.export_csv)
        self.tree.bind("<Button-3>", self.show_menu)

    def add_menu(self):
        """添加菜单栏"""
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="配置", command=self.open_config)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.quit)
        menubar.add_cascade(label="文件", menu=file_menu)

        tool_menu = tk.Menu(menubar, tearoff=0)
        tool_menu.add_command(label="网络诊断", command=self.open_diagnostics)
        tool_menu.add_command(label="历史记录", command=self.open_history)
        menubar.add_cascade(label="工具", menu=tool_menu)

        proxy_menu = tk.Menu(menubar, tearoff=0)
        proxy_menu.add_command(label="配置系统代理", command=self.configure_system_proxy)
        menubar.add_cascade(label="代理", menu=proxy_menu)

        self.config(menu=menubar)

    def configure_system_proxy(self):
        """配置系统代理"""
        proxy_settings = self.app_config['proxy_settings']
        enable = not proxy_settings['enable']
        server = f"127.0.0.1:{proxy_settings.get('port', 1080)}"
        bypass = ''

        if SystemProxy.configure_proxy(enable=enable, server=server, bypass=bypass):
            self.app_config['proxy_settings']['enable'] = enable
            ConfigManager.save_config(self.app_config)
            messagebox.showinfo("系统代理", f"系统代理已{'启用' if enable else '禁用'}")
        else:
            messagebox.showerror("系统代理", "配置系统代理失败，仅支持Windows系统。")

    def open_config(self):
        """打开配置窗口"""
        ConfigWindow(self, self)

    def open_diagnostics(self):
        """打开网络诊断窗口"""
        DiagnosticsWindow(self)

    def open_history(self):
        """打开历史记录窗口"""
        HistoryWindow(self)

    def open_bgacn(self):
        """打开 Cloudflare 网站优选窗口（目标域名可改，默认 bgacn.com）"""
        BGACNWindow(self)

    def start_scan(self):
        """开始扫描"""
        if self.running:
            return

        self.running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status.config(text="扫描中...")
        self.progress_bar.start(10)

        self.tree.delete(*self.tree.get_children())
        self.results = []

        ip_type = self.ip_type.get()
        count = int(self.test_count.get())

        threading.Thread(target=self.run_scan, args=(ip_type, count)).start()

    def stop_scan(self):
        """停止扫描"""
        if self.running:
            self.running = False
            self.status.config(text="停止扫描...")

    def run_scan(self, ip_type, count):
        """执行扫描"""
        executor = ThreadPoolExecutor(max_workers=self.app_config['max_threads'])
        ips = self.scanner.generate_ips(ip_type, count)
        futures = [executor.submit(self.scanner.test_latency, ip, timeout=self.app_config['timeout'], proxy_config=self.app_config['proxy_settings']) for ip in ips]

        completed_count = 0
        total_count = len(ips)
        temp_results_for_ui = []

        for future in futures:
            if not self.running:
                executor.shutdown(wait=False)
                break

            result = future.result()
            self.results.append(result)
            completed_count += 1
            self.update_progress(completed_count, total_count)

            if result['https_avg']:
                temp_results_for_ui.append(result)

        executor.shutdown(wait=True)

        analyzed_results = self.scanner.analyze_results(temp_results_for_ui)
        if analyzed_results:
             for result in analyzed_results:
                self.tree.insert('', 'end', values=(
                    result['ip'],
                    f"{result['tcp_avg']:.1f}" if result['tcp_avg'] is not None else '超时',
                    f"{result['http_avg']:.1f}" if result['http_avg'] is not None else '超时',
                    f"{result['https_avg']:.1f}" if result['https_avg'] is not None else '超时',
                    result.get('score', '')
                ))
             self.history_manager.add_record(analyzed_results[:10])
        else:
            messagebox.showinfo("扫描结果", "没有找到可用的 Cloudflare IP。")

        self.running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress_bar.stop()
        self.progress_var.set(0)
        self.status.config(text="扫描完成")
        if analyzed_results:
            messagebox.showinfo("扫描结果", f"扫描完成，找到 {len(analyzed_results)} 个可用 IP。最佳IP: {analyzed_results[0]['ip'] if analyzed_results else 'N/A'}")

    def update_progress(self, completed, total):
        """更新进度条"""
        percent = (completed / total) * 100
        self.progress_var.set(percent)
        self.status.config(text=f"扫描中... ({completed}/{total} - {percent:.1f}%)")
        self.update_idletasks()

    def apply_hosts(self):
        """应用到 Hosts 文件"""
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showinfo("应用到Hosts", "请在结果表格中选择要应用的IP地址。")
            return

        selected_ips_results = []
        for item_id in selected_items:
            item_values = self.tree.item(item_id, 'values')
            ip_address = item_values[0]
            for result in self.results:
                if result['ip'] == ip_address:
                    selected_ips_results.append(result)
                    break

        if not selected_ips_results:
            messagebox.showerror("应用到Hosts", "无法获取所选IP的详细信息，应用Hosts失败。")
            return

        os_type = platform.system()
        if os_type == 'Windows':
            hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        elif os_type == 'Linux' or os_type == 'Darwin':
            hosts_path = "/etc/hosts"
        else:
            messagebox.showerror("应用到Hosts", f"不支持的操作系统: {os_type}，无法确定Hosts文件路径。")
            return

        if Exporter.export_hosts(selected_ips_results, hosts_path):
            messagebox.showinfo("应用到Hosts", f"成功将选定的IP应用到 Hosts 文件: {hosts_path}，可能需要管理员权限。")
        else:
            messagebox.showerror("应用到Hosts", f"应用 Hosts 文件失败: {hosts_path}，请检查权限或文件是否存在。")

    def load_history(self):
        """加载历史记录"""
        pass

    def show_menu(self, event):
        """显示右键菜单"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.menu.post(event.x_root, event.y_root)

    def export_hosts(self):
        """导出 Hosts 文件"""
        if not self.results:
            messagebox.showinfo("导出", "没有扫描结果可以导出。")
            return
        filepath = filedialog.asksaveasfilename(defaultextension=".hosts", filetypes=[("Hosts 文件", "*.hosts"), ("所有文件", "*.*")])
        if filepath:
            best_results = self.scanner.analyze_results(self.results)
            if best_results:
                if Exporter.export_hosts(best_results, filepath):
                    messagebox.showinfo("导出", "成功导出到 Hosts 文件。")
                else:
                    messagebox.showerror("导出", "导出 Hosts 文件失败。")
            else:
                 messagebox.showinfo("导出", "没有有效的扫描结果可以导出。")

    def export_json(self):
        """导出 JSON 文件"""
        if not self.results:
            messagebox.showinfo("导出", "没有扫描结果可以导出。")
            return
        filepath = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON 文件", "*.json"), ("所有文件", "*.*")])
        if filepath:
            best_results = self.scanner.analyze_results(self.results)
            if best_results:
                if Exporter.export_json(best_results, filepath):
                    messagebox.showinfo("导出", "成功导出到 JSON 文件。")
                else:
                    messagebox.showerror("导出", "导出 JSON 文件失败。")
            else:
                 messagebox.showinfo("导出", "没有有效的扫描结果可以导出。")

    def export_csv(self):
        """导出 CSV 文件"""
        if not self.results:
            messagebox.showinfo("导出", "没有扫描结果可以导出。")
            return
        filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV 文件", "*.csv"), ("所有文件", "*.*")])
        if filepath:
             best_results = self.scanner.analyze_results(self.results)
             if best_results:
                if Exporter.export_csv(best_results, filepath):
                    messagebox.showinfo("导出", "成功导出到 CSV 文件。")
                else:
                    messagebox.showerror("导出", "导出 CSV 文件失败。")
             else:
                 messagebox.showinfo("导出", "没有有效的扫描结果可以导出。")

def clash_yaml_text(ip, target):
    """纯直连 Clash 配置：无需任何节点订阅，导入即加速 target。"""
    return f"""# {target} 优选 IP 最小配置（纯直连，无需任何节点订阅）
# 导入 Clash / ClashMeta / Clash Verge 后开 TUN/系统代理即生效
mixed-port: 7890
allow-lan: false
mode: Rule
log-level: info
unified-delay: true

dns:
  enable: true
  nameserver:
    - 223.5.5.5
    - 119.29.29.29

hosts:
  {target}: {ip}
  "+.{target}": {ip}

rules:
  - DOMAIN-SUFFIX,{target},DIRECT
  - MATCH,DIRECT
"""


def clash_merge_text(ip, target):
    """Clash Verge「覆写合并」片段：挂到已有订阅/配置上，更新不丢。"""
    return f"""# Clash Verge 覆写合并片段：{target} -> {ip}
dns:
  enable: true
hosts:
  {target}: {ip}
  "+.{target}": {ip}
rules:
  - DOMAIN-SUFFIX,{target},DIRECT
"""


# Magisk 模块安装脚本（Magisk 20.4+ 标准模板）
MAGISK_UPDATE_BINARY = """#!/sbin/sh
umask 022
ui_print() { echo "$1"; }
require_new_magisk() {
  ui_print "*******************************"
  ui_print " Please install Magisk v20.4+! "
  ui_print "*******************************"
  exit 1
}
OUTFD=$2
ZIPFILE=$3
mount /data 2>/dev/null
[ -f /data/adb/magisk/util_functions.sh ] || require_new_magisk
. /data/adb/magisk/util_functions.sh
[ $MAGISK_VER_CODE -lt 20400 ] && require_new_magisk
install_module
exit 0
"""


def magisk_module_zip(path, ip, target):
    """生成 Magisk 模块 zip（systemless hosts，需 root 刷入），返回 (ok, msg)。"""
    safe = ''.join(c if c.isalnum() else '-' for c in target.lower()).strip('-')
    names = [target] if target.startswith('www.') else [target, f'www.{target}']
    hosts = ["127.0.0.1       localhost", "::1             localhost", "",
             f"# cf-ip-finder {target} -> {ip}"] + [f"{ip}    {n}" for n in names]
    prop = (f"id=cf-hosts-{safe}\n"
            f"name=CF优选hosts-{target}\n"
            f"version=v1.4.0\n"
            f"versionCode=14000\n"
            f"author=cosmo\n"
            f"description={target} -> {ip} Cloudflare 优选 IP（systemless hosts）\n")
    try:
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("META-INF/com/google/android/update-binary", MAGISK_UPDATE_BINARY)
            z.writestr("META-INF/com/google/android/updater-script", "#MAGISK\n")
            z.writestr("module.prop", prop)
            z.writestr("system/etc/hosts", "\n".join(hosts) + "\n")
    except OSError as e:
        return False, f"写入失败: {e}"
    return (True, f"已生成 Magisk 模块 -> {path}\n"
                  f"      {target} -> {ip}（Magisk 里「从本地安装」刷入，重启生效，需 root）")


def run_bgacn_cli(argv):
    """Cloudflare 站点优选命令行模式: python cf_ip_scanner.py bgacn [--apply|--remove|--yaml|--merge]"""
    ap = argparse.ArgumentParser(
        prog="cf_ip_scanner.py bgacn",
        description="托管在 Cloudflare 上网站的优选 IP（SNI 握手测速 + 稳定性排序，默认 bgacn.com）",
    )
    ap.add_argument("--target", default="bgacn.com", help="目标域名（默认 bgacn.com）")
    ap.add_argument("--count", type=int, default=800, help="采样 IP 数量（默认 800）")
    ap.add_argument("--reps", type=int, default=3, help="每个 IP 握手次数（默认 3）")
    ap.add_argument("--timeout", type=float, default=3.0, help="单次握手超时秒（默认 3）")
    ap.add_argument("--top", type=int, default=10, help="展示前 N 个结果（默认 10）")
    ap.add_argument("--workers", type=int, default=120, help="并发线程数（默认 120）")
    ap.add_argument("--ip", help="直接指定优选 IP、跳过扫描（配合 --apply/--yaml/--merge）")
    ap.add_argument("--apply", action="store_true", help="把最稳的 IP 写入 hosts（需管理员）")
    ap.add_argument("--remove", action="store_true", help="从 hosts 移除本工具写入的条目")
    ap.add_argument("--yaml", metavar="FILE", help="生成 Clash 独立配置（纯直连，无需订阅）到 FILE")
    ap.add_argument("--merge", metavar="FILE", help="生成 Clash Verge 覆写合并片段到 FILE")
    ap.add_argument("--magisk", metavar="FILE", help="生成 Magisk 模块 zip（systemless hosts，需 root）到 FILE")
    ap.add_argument("--json", help="把结果存成 JSON 文件")
    args = ap.parse_args(argv)

    scanner = BGACNTargetScanner(args.target, args.reps, args.timeout)

    if args.remove:
        ok, msg = scanner.remove_hosts()
        print(("[+] " if ok else "[*] ") + msg)
        return 0

    if args.ip:
        best = {"ip": args.ip}
    else:
        t0 = time.time()
        good = scanner.scan(args.count, workers=args.workers)
        dt = time.time() - t0

        if not good:
            print("[-] 没有找到可用 IP，可增大 --count 或 --timeout 重试。")
            return 1

        print(f"\n[+] 扫描完成 {dt:.0f}s | 可用 {len(good)} 个 IP（稳定性优先排序）\n")
        print(f"{'IP':<16} {'命中':>8} {'平均握手':>10} {'最差握手':>10}")
        for r in good[: args.top]:
            print(f"{r['ip']:<16} {r['hits']}/{r['reps']:<6} {r['avg'] * 1000:>7.0f}ms {r['worst'] * 1000:>7.0f}ms")

        best = good[0]
        print(f"\n[★] 最稳 IP: {best['ip']}（命中 {best['hits']}/{best['reps']}，平均握手 {best['avg'] * 1000:.0f}ms）")

        if args.json:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump({
                    'generated': time.time(),
                    'target': args.target,
                    'results': good[:50],
                }, f, indent=2, ensure_ascii=False)
            print(f"[+] 结果已存 -> {args.json}")

    if args.yaml:
        try:
            with open(args.yaml, "w", encoding="utf-8") as f:
                f.write(clash_yaml_text(best["ip"], args.target))
            print(f"[+] 已生成 Clash 独立配置 -> {args.yaml}\n      {args.target} -> {best['ip']}（纯直连，无需订阅）")
        except OSError as e:
            print(f"[!] 写入失败: {e}")

    if args.merge:
        try:
            with open(args.merge, "w", encoding="utf-8") as f:
                f.write(clash_merge_text(best["ip"], args.target))
            print(f"[+] 已生成覆写合并片段 -> {args.merge}\n      {args.target} -> {best['ip']}（挂到订阅上即可）")
        except OSError as e:
            print(f"[!] 写入失败: {e}")

    if args.magisk:
        ok, msg = magisk_module_zip(args.magisk, best["ip"], args.target)
        print(("[+] " if ok else "[!] ") + msg)

    if args.apply:
        ok, msg = scanner.apply_hosts(best["ip"])
        print(("[+] " if ok else "[-] ") + msg)
        return 0 if ok else 1

    if not (args.yaml or args.merge or args.magisk):
        print("\n[*] 加 --apply 写入 hosts 生效（管理员运行）；"
              "或 --yaml / --merge / --magisk 导出配置给手机等设备用。")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "bgacn":
        sys.exit(run_bgacn_cli(sys.argv[2:]))
    app = Application()
    app.mainloop()