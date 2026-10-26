#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cf_hosts.py — 把 CloudflareSpeedTest 的测速结果写入 hosts

配合 C:/coding/_cfst/cfst.exe 使用。
用法：
  python cf_hosts.py --domain bgacn.com            # 用已有 result.csv 写 hosts
  python cf_hosts.py --domain bgacn.com --run      # 先跑 cfst.exe 再写
  python cf_hosts.py --show                        # 查看 hosts 托管段
  python cf_hosts.py --clean                       # 移除托管段
  python cf_hosts.py --domain x.com --top 3        # 写入前 3 个 IP
"""

from __future__ import annotations

import argparse
import csv
import os
import shutil
import subprocess
import sys
import time

MARK_BEGIN = "# ==== BEGIN cf_hosts managed block (do not edit) ===="
MARK_END = "# ==== END cf_hosts managed block ===="
# 旧版 bgacn_fix.py 的标记，写入时一并清掉，避免同域名两套 IP 打架
LEGACY_MARKS = (
    ("# ==== BEGIN bgacn_fix managed block (do not edit) ====",
     "# ==== END bgacn_fix managed block ===="),
)

HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
if os.name != "nt":
    HOSTS_PATH = "/etc/hosts"

# cfst.exe 所在目录（和本脚本同级的 _cfst/）
HERE = os.path.dirname(os.path.abspath(__file__))
CFST_DIR = os.path.join(HERE, "_cfst")
CFST_EXE = os.path.join(CFST_DIR, "cfst.exe")
RESULT_CSV = os.path.join(CFST_DIR, "result.csv")


def run_cfst(extra: list[str] | None = None) -> int:
    if not os.path.isfile(CFST_EXE):
        print(f"[!] 找不到 {CFST_EXE}")
        print("    先去 https://github.com/XIU2/CloudflareSpeedTest/releases 下载解压到 _cfst/")
        return 2
    cmd = [CFST_EXE, "-o", RESULT_CSV]
    if extra:
        cmd += extra
    print(f"[*] 运行 CloudflareSpeedTest（可能要几分钟）...")
    print(f"    {' '.join(cmd)}")
    # cfst.exe 结束时会等回车，喂一个空输入让它直接退出
    r = subprocess.run(cmd, cwd=CFST_DIR, stdin=subprocess.DEVNULL)
    return r.returncode


def read_top_ips(csv_path: str, n: int) -> list[tuple[str, float, float]]:
    """返回 [(ip, 延迟, 下载速度)]，按 CFST 输出顺序（已排序）。"""
    if not os.path.isfile(csv_path):
        print(f"[!] 找不到结果文件：{csv_path}")
        return []
    out: list[tuple[str, float, float]] = []
    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = (row.get("IP 地址") or row.get("IP") or "").strip()
            if not ip:
                continue
            try:
                lat = float(row.get("平均延迟") or 0)
                spd = float(row.get("下载速度(MB/s)") or 0)
            except ValueError:
                lat, spd = 0.0, 0.0
            out.append((ip, lat, spd))
            if len(out) >= n:
                break
    return out


def _strip_block(text: str, begin: str, end: str) -> str:
    if begin not in text:
        return text
    before, rest = text.split(begin, 1)
    _mid, after = rest.split(end, 1)
    return before + after.lstrip("\n")


def hosts_split(text: str) -> tuple[str, str, str]:
    # 先清掉旧标记块
    for b, e in LEGACY_MARKS:
        text = _strip_block(text, b, e)
    if MARK_BEGIN not in text:
        return text, "", ""
    before, rest = text.split(MARK_BEGIN, 1)
    mid, after = rest.split(MARK_END, 1)
    return before, MARK_BEGIN + mid + MARK_END, after


def render_block(domain: str, ips: list[str]) -> str:
    lines = [
        MARK_BEGIN,
        f"# domain: {domain}  updated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
    ]
    for ip in ips:
        lines.append(f"{ip}\t{domain}")
        lines.append(f"{ip}\twww.{domain}")
    lines.append(MARK_END)
    return "\n".join(lines) + "\n"


def write_hosts(domain: str, ips: list[str]) -> int:
    block = render_block(domain, ips)
    try:
        with open(HOSTS_PATH, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except PermissionError:
        print(f"[!] 读 hosts 无权限：{HOSTS_PATH}\n    请用管理员终端运行")
        return 2

    before, _old, after = hosts_split(text)
    new_text = before + block + after.lstrip("\n")
    if not new_text.endswith("\n"):
        new_text += "\n"

    try:
        with open(HOSTS_PATH, "w", encoding="utf-8", newline="\n") as f:
            f.write(new_text)
    except PermissionError:
        print(f"[!] 写 hosts 无权限：{HOSTS_PATH}\n    请用管理员终端运行")
        return 2

    print(f"[+] 已写入 hosts：{domain} / www.{domain} 各 {len(ips)} 条")
    for ip in ips:
        print(f"    {ip}\t{domain}")
    print("[*] 请执行  ipconfig /flushdns  后重开浏览器")
    return 0


def show_hosts() -> int:
    try:
        with open(HOSTS_PATH, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except PermissionError:
        print(f"[!] 读 hosts 无权限")
        return 2
    _, mid, _ = hosts_split(text)
    print(mid if mid else "[*] hosts 中没有托管段")
    return 0


def clean_hosts() -> int:
    try:
        with open(HOSTS_PATH, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except PermissionError:
        print(f"[!] 读 hosts 无权限")
        return 2
    before, mid, after = hosts_split(text)
    if not mid:
        print("[*] 没有托管段，无需清理")
        return 0
    new_text = before + after.lstrip("\n")
    if not new_text.endswith("\n"):
        new_text += "\n"
    try:
        with open(HOSTS_PATH, "w", encoding="utf-8", newline="\n") as f:
            f.write(new_text)
    except PermissionError:
        print(f"[!] 写 hosts 无权限")
        return 2
    print("[+] 已移除托管段")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="CloudflareSpeedTest 结果写入 hosts")
    ap.add_argument("--domain", default="bgacn.com", help="目标域名，默认 bgacn.com")
    ap.add_argument("--run", action="store_true", help="写入前先跑一次 cfst.exe")
    ap.add_argument("--csv", default=RESULT_CSV, help="结果 csv 路径")
    ap.add_argument("--top", type=int, default=2, help="写入前 N 个 IP，默认 2")
    ap.add_argument("--show", action="store_true")
    ap.add_argument("--clean", action="store_true")
    ap.add_argument("--cfst-args", default="", help="透传给 cfst.exe 的额外参数，如 '-tl 200 -dn 5'")
    args = ap.parse_args()

    if args.show:
        return show_hosts()
    if args.clean:
        return clean_hosts()

    if args.run:
        extra = args.cfst_args.split() if args.cfst_args else None
        rc = run_cfst(extra)
        if rc != 0:
            return rc

    top = read_top_ips(args.csv, args.top)
    if not top:
        print("[!] 没有可用 IP。先运行：python cf_hosts.py --run")
        return 1

    print(f"[*] 将写入 {args.domain}：")
    for ip, lat, spd in top:
        print(f"    {ip:<18} 延迟 {lat:.0f} ms  速度 {spd:.2f} MB/s")

    return write_hosts(args.domain, [ip for ip, _, _ in top])


if __name__ == "__main__":
    sys.exit(main())
