#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cf-ip-finder GUI — 托管在 Cloudflare 上网站的优选 IP 图形界面

为指定的 Cloudflare 托管网站优选可直连的 CF IP（默认 bgacn.com，
「目标域名」输入框可改成任意托管在 Cloudflare 的网站）。
与命令行版共用同一套扫描/hosts/导出逻辑（bgacn_ip_finder.py），纯标准库（tkinter）。

用法:
  python bgacn_ip_finder_gui.py
  python bgacn_ip_finder.py --gui
"""

import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

import bgacn_ip_finder as core


class BGACNApp(tk.Tk):
    """优选 IP 主窗口"""

    def __init__(self):
        super().__init__()
        self.title("Cloudflare 网站优选 IP 工具（默认 bgacn.com）")
        self.geometry("680x520")
        self.running = False
        self.results = []
        self._build_ui()

    def _build_ui(self):
        row1 = ttk.Frame(self)
        row1.pack(pady=8, fill=tk.X, padx=10)

        ttk.Label(row1, text="目标域名:").grid(row=0, column=0, padx=5)
        self.target_entry = ttk.Entry(row1, width=16)
        self.target_entry.insert(0, core.DEFAULT_TARGET)  # 默认 bgacn.com，可改成任意 CF 网站
        self.target_entry.grid(row=0, column=1, padx=5)

        ttk.Label(row1, text="测试数量:").grid(row=0, column=2, padx=5)
        self.count_spin = ttk.Spinbox(row1, from_=50, to=5000, width=6)
        self.count_spin.set(800)
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

        columns = ('ip', 'hits', 'avg', 'worst')
        self.tree = ttk.Treeview(self, columns=columns, show='headings', selectmode='browse')
        self.tree.heading('ip', text='IP地址')
        self.tree.heading('hits', text='命中')
        self.tree.heading('avg', text='平均握手(ms)')
        self.tree.heading('worst', text='最差握手(ms)')
        self.tree.column('hits', anchor='center', width=80)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)

        self.status = ttk.Label(
            self,
            text="目标域名可改成任何托管在 Cloudflare 的网站 | 以目标站 SNI 测 TLS 握手，按稳定性排序 | 写入 hosts 需管理员权限",
            relief=tk.SUNKEN, anchor='w',
        )
        self.status.pack(fill=tk.X, side=tk.BOTTOM)

    # ---------------- 扫描 ----------------
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
        target = self.target_entry.get().strip() or core.DEFAULT_TARGET
        reps = int(self.reps_spin.get())
        timeout = float(self.timeout_spin.get())
        count = int(self.count_spin.get())
        self._log(f"[*] 目标 {target} | 扫描 {count} 个 Cloudflare IP | 每个 {reps} 次握手 ...")
        try:
            good = core.scan(target, count, reps, timeout, log=self._log, cancel=lambda: not self.running)
        except Exception as e:
            self.after(0, self._finish_scan, [], f"扫描出错: {e}")
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
            best = good[0]
            self.status.config(
                text=f"完成 | 可用 {len(good)} 个 IP，最稳: {best['ip']}"
                     f"（命中 {best['hits']}/{best['reps']}，平均 {best['avg'] * 1000:.0f}ms）"
            )
        else:
            self.status.config(text="没有找到可用 IP，可增大测试数量或超时重试。")

    # ---------------- hosts ----------------
    def _target(self):
        return self.target_entry.get().strip() or core.DEFAULT_TARGET

    def apply_hosts(self):
        if not self.results:
            messagebox.showinfo("写入Hosts", "请先运行优选。")
            return
        sel = self.tree.selection()
        ip = self.tree.item(sel[0], 'values')[0] if sel else self.results[0]['ip']
        ok, msg = core.apply_hosts(ip, self._target())
        (messagebox.showinfo if ok else messagebox.showerror)("写入Hosts", msg)

    def remove_hosts(self):
        ok, msg = core.remove_hosts()
        messagebox.showinfo("从Hosts移除", msg)

    # ---------------- Clash 导出 ----------------
    def _pick_ip(self):
        """选中行的 IP，没选就用最稳的。"""
        sel = self.tree.selection()
        return self.tree.item(sel[0], 'values')[0] if sel else self.results[0]['ip']

    def _export(self, kind):
        if not self.results:
            messagebox.showinfo("导出", "请先运行优选。")
            return
        ip = self._pick_ip()
        target = self._target()
        is_yaml = kind == "yaml"
        path = filedialog.asksaveasfilename(
            title="生成 Clash 独立配置" if is_yaml else "生成 Clash Verge 覆写合并片段",
            defaultextension=".yaml",
            initialfile=f"{target}-clash.yaml" if is_yaml else f"{target}-merge.yaml",
            filetypes=[("YAML", "*.yaml *.yml"), ("所有文件", "*.*")],
        )
        if not path:
            return
        ok, msg = (core.export_yaml if is_yaml else core.export_merge)(path, ip, target)
        (messagebox.showinfo if ok else messagebox.showerror)("导出", msg)
        self.status.config(text=msg.splitlines()[0])

    def export_yaml(self):
        """生成 Clash 独立配置（纯直连，无需订阅）。"""
        self._export("yaml")

    def export_merge(self):
        """生成 Clash Verge 覆写合并片段（挂到订阅上用）。"""
        self._export("merge")


def run_gui():
    app = BGACNApp()
    app.mainloop()


if __name__ == "__main__":
    run_gui()
