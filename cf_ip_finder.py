#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cf-ip-finder — 托管在 Cloudflare 上网站的优选 IP 工具

为指定的 Cloudflare 托管网站优选可直连的 CF IP（默认 bgacn.com）：
  * 只用 Python 标准库（无需 pip install）
  * 直接以 SNI=<target> 做 TLS 握手测速（命中被 GFW 掐的正是这一步）
  * 校验证书 + HTTP 200，确认该 IP 真的在服务目标站
  * 多次采样按「稳定性」排序，而不是单次最快（单次最快往往最抖）
  * --apply 一键写入 Windows hosts，--remove 撤销
  * --yaml / --merge 导出 Clash 配置 / Clash Verge 覆写片段（手机、路由器等
    不方便改 hosts 的场景，把优选 IP 交给 Clash 生效）

用法:
  python cf_ip_finder.py                 # 扫描并打印最稳的 IP
  python cf_ip_finder.py --gui           # 启动图形界面
  python cf_ip_finder.py --apply         # 扫描并把最优 IP 写入 hosts（需管理员）
  python cf_ip_finder.py --remove        # 从 hosts 删除本工具写入的条目
  python cf_ip_finder.py --yaml c.yaml --merge m.yaml   # 扫描并导出 Clash 配置
  python cf_ip_finder.py --ip 1.2.3.4 --yaml c.yaml     # 指定 IP 直接生成，不扫描
  python cf_ip_finder.py --magisk m.zip                 # 导出 Magisk 模块（root 手机直刷）
  python cf_ip_finder.py --target example.com --count 1500 --reps 5
"""

import argparse
import ipaddress
import json
import random
import socket
import ssl
import sys
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---- 默认目标（可用 --target 换成任何托管在 Cloudflare 的网站）----
DEFAULT_TARGET = "bgacn.com"
HOSTS_TAG = "bgacn-ip-finder"  # hosts 条目注释标记，--remove 靠它识别

# Cloudflare 官方 IPv4 段
CF_RANGES = [
    "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13",
    "162.158.0.0/15", "108.162.192.0/18", "131.0.72.0/22",
    "141.101.64.0/18", "173.245.48.0/20", "188.114.96.0/20",
    "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
]


def sample_ips(count, seed=20261026):
    """从 CF 网段里均匀采样 count 个 IP。"""
    random.seed(seed)
    per = max(1, count // len(CF_RANGES))
    out, seen = [], set()
    for cidr in CF_RANGES:
        net = ipaddress.ip_network(cidr)
        hosts = list(net.hosts())
        picks = random.sample(hosts, min(per, len(hosts)))
        for h in picks:
            s = str(h)
            if s not in seen:
                seen.add(s)
                out.append(s)
    random.shuffle(out)
    return out[:count]


def _probe_once(ip, sni, timeout):
    """单次握手测试，返回 tls 耗时或 None。校验证书覆盖 sni。"""
    try:
        t0 = time.perf_counter()
        raw = socket.create_connection((ip, 443), timeout=timeout)
        raw.settimeout(timeout)
        ctx = ssl.create_default_context()
        try:
            ss = ctx.wrap_socket(raw, server_hostname=sni)
        except ssl.SSLError:
            raw.close()
            return None  # 证书不匹配 / 被掐
        tls = time.perf_counter() - t0
        # 确认证书确实覆盖目标域（防止连到别的 CF 客户）
        cert = ss.getpeercert()
        names = [v for t, v in cert.get("subjectAltName", ()) if t == "DNS"]
        if not _cert_matches(sni, names):
            ss.close()
            return None
        # 确认真的返回 200
        ss.sendall(
            f"HEAD / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n"
            f"User-Agent: bgacn-ip-finder\r\n\r\n".encode()
        )
        head = ss.recv(200)
        ss.close()
        if b"HTTP/" in head:
            try:
                code = int(head.split()[1])
            except Exception:
                return None
            if code == 200:
                return tls
        return None
    except Exception:
        return None


def _cert_matches(host, names):
    """简易通配符匹配：*.bgacn.com 或 bgacn.com。"""
    import fnmatch
    for n in names:
        if n == host or fnmatch.fnmatch(host, n):
            return True
    return False


def probe_ip(ip, sni, reps, timeout):
    """对单个 IP 做 reps 次握手，返回稳定性统计。"""
    times = []
    for _ in range(reps):
        t = _probe_once(ip, sni, timeout)
        if t is not None:
            times.append(t)
        time.sleep(0.05)
    if not times:
        return {"ip": ip, "ok": False, "hits": 0, "reps": reps}
    return {
        "ip": ip,
        "ok": True,
        "hits": len(times),
        "reps": reps,
        "avg": sum(times) / len(times),
        "worst": max(times),
        "best": min(times),
        "rate": len(times) / reps,
    }


def scan(sni, count, reps, timeout, workers=120, log=print, cancel=None):
    ips = sample_ips(count)
    log(f"[*] 目标 {sni} | 扫描 {len(ips)} 个 Cloudflare IP | 每个 {reps} 次握手 ...")
    results = []
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(probe_ip, ip, sni, reps, timeout): ip for ip in ips}
        for f in as_completed(futs):
            if cancel and cancel():
                for pending in futs:
                    pending.cancel()
                break
            results.append(f.result())
            done += 1
            if done % 200 == 0:
                okc = sum(1 for r in results if r["ok"])
                log(f"    进度 {done}/{len(ips)}  可用 {okc}")
    good = [r for r in results if r["ok"]]
    # 稳定性优先：命中率降序 → 平均耗时升序 → 最差耗时升序
    good.sort(key=lambda r: (-r["rate"], r["avg"], r["worst"]))
    return good


# ---------------- hosts 写入 ----------------
HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"


def _read_hosts():
    with open(HOSTS_PATH, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _host_names(target):
    """目标域 + 对应 www 变体。"""
    if target.startswith("www."):
        base = target[4:]
        return [target, base]
    return [target, f"www.{target}"]


def _strip_target_lines(data, names):
    """删掉任何映射到这些域名的 hosts 行（含注释行），避免重复映射。"""
    keys = set(names)
    out, changed = [], False
    for line in data.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            # 命中本工具注释一并清掉
            if HOSTS_TAG in line:
                changed = True
                continue
            out.append(line)
            continue
        fields = s.split()
        # 形如: <ip>  host1 host2 ...
        if len(fields) >= 2 and keys.intersection(fields[1:]):
            changed = True
            continue
        out.append(line)
    return out, changed


def apply_hosts(ip, target):
    """把最优 IP 写入 hosts（旧映射已清除），返回 (ok, msg)。"""
    names = _host_names(target)
    try:
        data = _read_hosts()
        out, _ = _strip_target_lines(data, names)
        block = ["", f"# {HOSTS_TAG} {target} -> {ip}"]
        for n in names:
            block.append(f"{ip}    {n}    # {HOSTS_TAG}")
        with open(HOSTS_PATH, "w", encoding="ascii", errors="replace") as f:
            f.write("\n".join(out).rstrip() + "\n" + "\n".join(block) + "\n")
    except PermissionError:
        return False, "写入 hosts 需要管理员权限，请用管理员身份运行。"
    except OSError as e:
        return False, f"hosts 操作失败: {e}"
    msg = f"已写入 hosts（旧映射已清除）: {target} -> {ip}\n" + "\n".join(f"      {ip}    {n}" for n in names)
    return True, msg


def remove_hosts():
    """从 hosts 移除本工具写入的条目（按注释标记识别），返回 (ok, msg)。"""
    try:
        data = _read_hosts()
        lines = data.splitlines()
        out = [line for line in lines if HOSTS_TAG not in line]
        if len(out) == len(lines):
            return False, "hosts 里没有本工具写入的条目。"
        with open(HOSTS_PATH, "w", encoding="ascii", errors="replace") as f:
            f.write("\n".join(out).rstrip() + "\n")
    except PermissionError:
        return False, "写入 hosts 需要管理员权限，请用管理员身份运行。"
    except OSError as e:
        return False, f"hosts 操作失败: {e}"
    return True, "已从 hosts 移除本工具写入的条目。"


# ---------------- Clash 配置导出 ----------------
def _clash_yaml_text(ip, target):
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


def _clash_merge_text(ip, target):
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


def export_yaml(path, ip, target):
    """生成 Clash 独立配置（纯直连 + 优选 IP 映射），返回 (ok, msg)。"""
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(_clash_yaml_text(ip, target))
    except OSError as e:
        return False, f"写入失败: {e}"
    return True, f"已生成 Clash 独立配置 -> {path}\n      {target} -> {ip}（纯直连，无需订阅）"


def export_merge(path, ip, target):
    """生成 Clash Verge 覆写合并片段，返回 (ok, msg)。"""
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(_clash_merge_text(ip, target))
    except OSError as e:
        return False, f"写入失败: {e}"
    return True, f"已生成覆写合并片段 -> {path}\n      {target} -> {ip}（挂到订阅上即可）"


# Magisk 模块安装脚本（Magisk 20.4+ 标准模板）
_MAGISK_UPDATE_BINARY = """#!/sbin/sh
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


def _magisk_hosts_text(ip, target):
    """模块里的 system/etc/hosts：安卓标准 localhost 表头 + 目标域映射。"""
    lines = ["127.0.0.1       localhost", "::1             localhost", "",
             f"# cf-ip-finder {target} -> {ip}"]
    for n in _host_names(target):
        lines.append(f"{ip}    {n}")
    return "\n".join(lines) + "\n"


def export_magisk(path, ip, target):
    """生成 Magisk 模块 zip（systemless hosts，需 root 刷入），返回 (ok, msg)。"""
    safe = ''.join(c if c.isalnum() else '-' for c in target.lower()).strip('-')
    prop = (f"id=cf-hosts-{safe}\n"
            f"name=CF优选hosts-{target}\n"
            f"version=v1.4.0\n"
            f"versionCode=14000\n"
            f"author=cosmo\n"
            f"description={target} -> {ip} Cloudflare 优选 IP（systemless hosts）\n")
    try:
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("META-INF/com/google/android/update-binary", _MAGISK_UPDATE_BINARY)
            z.writestr("META-INF/com/google/android/updater-script", "#MAGISK\n")
            z.writestr("module.prop", prop)
            z.writestr("system/etc/hosts", _magisk_hosts_text(ip, target))
    except OSError as e:
        return False, f"写入失败: {e}"
    return (True, f"已生成 Magisk 模块 -> {path}\n"
                  f"      {target} -> {ip}（Magisk 里「从本地安装」刷入，重启生效，需 root）")


# ---------------- 主入口 ----------------
def main():
    ap = argparse.ArgumentParser(
        description="托管在 Cloudflare 上网站的优选 IP 工具（默认 bgacn.com，--target 可改）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--target", default=DEFAULT_TARGET, help=f"目标域名（默认 {DEFAULT_TARGET}）")
    ap.add_argument("--count", type=int, default=800, help="采样 IP 数量（默认 800）")
    ap.add_argument("--reps", type=int, default=3, help="每个 IP 握手次数（默认 3）")
    ap.add_argument("--timeout", type=float, default=3.0, help="单次握手超时秒（默认 3）")
    ap.add_argument("--top", type=int, default=10, help="展示前 N 个（默认 10）")
    ap.add_argument("--ip", help="直接指定优选 IP、跳过扫描（配合 --apply/--yaml/--merge/--magisk）")
    ap.add_argument("--apply", action="store_true", help="把最稳的 IP 写入 Windows hosts（需管理员）")
    ap.add_argument("--remove", action="store_true", help="从 hosts 移除本工具写入的条目")
    ap.add_argument("--yaml", metavar="FILE", help="生成 Clash 独立配置（纯直连，无需订阅）到 FILE")
    ap.add_argument("--merge", metavar="FILE", help="生成 Clash Verge 覆写合并片段到 FILE")
    ap.add_argument("--magisk", metavar="FILE", help="生成 Magisk 模块 zip（systemless hosts，需 root）到 FILE")
    ap.add_argument("--gui", action="store_true", help="启动图形界面")
    ap.add_argument("--json", help="把结果存成 JSON 文件")
    args = ap.parse_args()

    if args.gui:
        from cf_ip_finder_gui import run_gui
        run_gui()
        return

    if args.remove:
        ok, msg = remove_hosts()
        print(("[+] " if ok else "[*] ") + msg)
        return

    if args.ip:
        best = {"ip": args.ip}
    else:
        t0 = time.time()
        good = scan(args.target, args.count, args.reps, args.timeout)
        dt = time.time() - t0

        if not good:
            print("[-] 没有找到可用 IP。可增大 --count 或 --timeout 重试。")
            sys.exit(1)

        print(f"\n[+] 扫描完成 {dt:.0f}s | 可用 {len(good)} 个 IP（稳定性优先排序）\n")
        print(f"{'IP':<16} {'命中':>7} {'平均':>8} {'最差':>8}")
        for r in good[: args.top]:
            print(f"{r['ip']:<16} {r['hits']}/{r['reps']:<5} {r['avg']*1000:>6.0f}ms {r['worst']*1000:>6.0f}ms")

        best = good[0]
        print(f"\n[★] 最稳 IP: {best['ip']}  (命中 {best['hits']}/{best['reps']}，平均 {best['avg']*1000:.0f}ms)")

        if args.json:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(good[:50], f, indent=2, ensure_ascii=False)
            print(f"[+] 结果已存 -> {args.json}")

    if args.yaml:
        ok, msg = export_yaml(args.yaml, best["ip"], args.target)
        print(("[+] " if ok else "[!] ") + msg)

    if args.merge:
        ok, msg = export_merge(args.merge, best["ip"], args.target)
        print(("[+] " if ok else "[!] ") + msg)

    if args.magisk:
        ok, msg = export_magisk(args.magisk, best["ip"], args.target)
        print(("[+] " if ok else "[!] ") + msg)

    if args.apply:
        ok, msg = apply_hosts(best["ip"], args.target)
        print(("[+] " if ok else "[!] ") + msg)
        if ok:
            print("\n[*] 完成。浏览器直接访问即可，无需代理。若日后又卡，重新跑一次 --apply。")
    elif not (args.yaml or args.merge or args.magisk):
        print("\n[*] 加 --apply 写入 hosts 生效（管理员运行）；"
              "或 --yaml / --merge / --magisk 导出配置给手机等设备用。")


if __name__ == "__main__":
    main()
