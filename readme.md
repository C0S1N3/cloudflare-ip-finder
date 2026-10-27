📜 **[查看更新日志](changelog.md)**

---

# 🚀 Cloudflare IP 优选工具

一个图形化的跨平台工具，帮助你找到最适合你的网络环境的 Cloudflare IP，提升访问速度，告别卡顿！

## ✨ 功能特性

这款小巧而强大的工具为你带来了以下功能：

- ✅ **简单易用**: 直观的图形界面，操作简单，无需复杂的命令行知识。
- 🎯 **CF 网站优选**: 为指定的 Cloudflare 托管网站以目标站 SNI 实测 TLS 握手、按稳定性排序，一键写 hosts 或导出 Clash 配置（详见下文）。
- ⚡ **多协议延迟测试**: 同时测试 TCP、HTTP 和 HTTPS 延迟，全方位评估 IP 质量。
- 📊 **智能评分系统**: 综合评估 IP 延迟，提供直观的评分，帮你快速找到最佳 IP。
- 📝 **多种导出格式**: 支持导出 Hosts 文件、JSON 和 CSV 格式，方便你灵活使用优选结果。
- 💾 **历史记录**: 记录你的测试历史，方便回顾和比较不同时段的网络状况。
- ⚙️ **灵活配置**: 自定义测试数量、线程数、超时时间等参数，满足你的个性化需求。
- 🌐 **IPv4 支持**: 目前专注于 IPv4 优选，未来可能扩展支持 IPv6。
- 🛡️ **系统代理支持**: 支持系统代理设置，方便在复杂网络环境下使用。
- 🔍 **网络诊断工具**: 内置路由追踪和 DNS 解析功能，辅助你进行网络问题排查。

## 🛠️ 使用方法

1. **下载运行**: 下载最新版本的工具压缩包，解压后直接运行主程序文件 (CloudFlareIPScanner.exe 或 cf_ip_scanner.py，取决于你的环境和打包方式)。
2. **配置参数**:
   - **IP 类型**: 目前仅支持 IPv4。
   - **测试数量**: 设置要测试的 IP 数量，数量越大，结果越精确，但耗时也越长。
   - **最大线程**: 设置并发测试的线程数，根据你的电脑性能和网络环境调整，过高可能导致网络拥堵或程序不稳定。
   - **超时时间**: 设置测试的超时时间，单位为秒。
   - **自动更新**: 勾选后，工具会在启动时检查是否有新版本。
   - **Cloudflare 域名列表**: 工具默认使用常用的 Cloudflare 域名进行测试，你也可以根据需要自定义域名列表。
   - **代理设置**: 在 "代理" 菜单中配置系统代理，如果你的网络环境需要代理才能访问外网，请务必配置。
3. **开始测试**: 点击 "开始测试" 按钮，工具将自动生成 Cloudflare IP 并进行延迟测试。
4. **查看结果**: 测试结果将显示在表格中，包括 IP 地址、TCP 延迟、HTTP 延迟、HTTPS 延迟和综合评分。表格会根据评分自动排序，评分越高，IP 质量越好。
5. **应用 Hosts**:
   - **选择 IP**: 在结果表格中选择你认为最佳的 IP (可以多选)。
   - **点击 "应用到Hosts" 按钮**: 工具会将选定的 IP 和配置的 Cloudflare 域名写入你的系统 Hosts 文件。 **注意：可能需要管理员权限才能修改 Hosts 文件。**
6. **导出结果**:
   - 右键点击结果表格，弹出菜单，选择 "导出到Hosts"、"导出为JSON" 或 "导出为CSV"，将测试结果保存到文件。
7. **网络诊断**: 在 "工具" 菜单中打开 "网络诊断" 窗口，可以使用路由追踪和 DNS 解析功能，输入目标地址进行网络诊断。
8. **查看历史**: 在 "工具" 菜单中打开 "历史记录" 窗口，查看之前的测试记录。

## 🎯 CF 网站优选

目标站（可指定任意托管在 Cloudflare 的网站）托管在 Cloudflare，默认 DNS 给出的 CF IP 在国内经常 TLS 握手被掐（握手 10 秒+ 或直接超时）。
通用模式拿 speed.cloudflare.com 等无关域名测延迟，对这种情况参考价值有限；本功能专为这类场景设计：

- **以目标站 SNI 实测握手**: 直接对候选 IP 做 `SNI=目标域名`（默认 bgacn.com）的 TLS 握手，被限速掐的正是这一步，测得才准。
- **校验真实性**: 证书必须覆盖目标域，且 `HEAD /` 返回 HTTP 200，确认该 IP 真的在服务目标站。
- **按稳定性排序**: 每个 IP 多次握手，按命中率降序排序（单次最快往往最抖），再看平均/最差握手耗时。
- **安全写 hosts**: 写入时自动清理目标域的旧映射，条目带 `cf-ip-finder:bgacn` 标记，可随时一键移除，不碰你自己写的 hosts。
- **导出 Clash 配置**: 一键生成 Clash 独立配置（纯直连、无需订阅）或 Clash Verge 覆写合并片段，手机/路由器等不方便改 hosts 的设备也能用。
- **导出 Magisk 模块**: root 手机可直接导出 Magisk 模块（systemless hosts），刷入重启即生效，连 Clash 都不用装。

**图形界面**：点击主界面的 "CF 网站优选" 按钮，设置目标域名（默认 bgacn.com，可改成任何托管在 Cloudflare 的网站）、测试数量、握手次数后点 "开始优选"，
完成后选中结果（不选则用最稳的）点 "写入Hosts"（需管理员权限），或点 "生成YAML"/"生成Merge"/"导出Magisk" 导出配置；"从Hosts移除" 可随时还原。

**命令行**（适合脚本化 / 定时重跑）：

```bash
# 扫描并打印最稳 IP
python cf_ip_scanner.py bgacn

# 扫描并写入 hosts（需管理员权限）
python cf_ip_scanner.py bgacn --apply

# 换 IP：重新跑一次即可（自动清理旧映射）
python cf_ip_scanner.py bgacn --apply

# 撤销：移除本工具写入的条目
python cf_ip_scanner.py bgacn --remove

# 生成 Clash 独立配置 / Clash Verge 覆写合并片段
python cf_ip_scanner.py bgacn --yaml clash.yaml --merge merge.yaml

# 生成 Magisk 模块（root 手机刷入，免 Clash）
python cf_ip_scanner.py bgacn --magisk module.zip

# 已有可用 IP 时直接生成，不扫描
python cf_ip_scanner.py bgacn --ip 1.2.3.4 --yaml clash.yaml

# 自定义参数
python cf_ip_scanner.py bgacn --target www.bgacn.com --count 1500 --reps 5 --json result.json
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `--target` | `bgacn.com` | 目标域名（任意托管在 Cloudflare 的网站） |
| `--count` | `800` | 采样 IP 数量 |
| `--reps` | `3` | 每个 IP 握手次数 |
| `--timeout` | `3.0` | 单次握手超时（秒） |
| `--top` | `10` | 展示前 N 个结果 |
| `--workers` | `120` | 并发线程数 |
| `--ip` | — | 直接指定 IP、跳过扫描 |
| `--apply` | — | 把最稳的 IP 写入 hosts |
| `--remove` | — | 从 hosts 移除本工具写入的条目 |
| `--yaml` | — | 生成 Clash 独立配置（纯直连，无需订阅） |
| `--merge` | — | 生成 Clash Verge 覆写合并片段（挂到订阅上用） |
| `--magisk` | — | 生成 Magisk 模块 zip（systemless hosts，需 root） |
| `--json` | — | 结果存成 JSON 文件 |

**独立版工具（零依赖）**: 仓库另附纯标准库实现的独立版 [bgacn_ip_finder.py](bgacn_ip_finder.py)（命令行）和 [bgacn_ip_finder_gui.py](bgacn_ip_finder_gui.py)（图形界面），不依赖 requests/dnspython，可直接双击打包的 exe 使用（见 [Releases](../../releases)）：

```bash
python bgacn_ip_finder_gui.py           # 启动图形界面
python bgacn_ip_finder.py --gui         # 同上
python bgacn_ip_finder.py --apply       # 命令行扫描并写入 hosts
python bgacn_ip_finder.py --yaml c.yaml --merge m.yaml   # 导出 Clash 配置
```

## 🧩 新手指南：怎么用 Clash 加速（小白向）

完全没用过 Clash 也没关系，照着做就行。**不需要"节点订阅"**，我们生成的配置是纯直连的。

**1. 装客户端（免费，二选一）**
- 安卓手机：应用商店或 GitHub 搜 **ClashMeta for Android**（或 FlClash），下载 apk 安装。
- Windows 电脑：搜 **Clash Verge Rev** 下载安装。

**2. 拿到配置（三选一）**
- **最简单**：点工具里「生成YAML」得到一个 `.yaml` 文件——直接用它。
- **已有订阅**：点「生成Merge」得到片段，在 Clash Verge 的「覆写合并」里粘贴，以后订阅更新也不丢。
- **root 手机**：点「导出Magisk」得到 zip，Magisk 里刷入重启即可，**根本不用装 Clash**。

**3. 导入配置**
- ClashMeta for Android：顶部「配置」→ 右下角 `+` → 「文件」→ 选生成的 yaml → 点选中它。
- Clash Verge：「订阅/配置」页 → 「新建」→「导入」→ 选文件。

**4. 开启加速**
- 手机：回首页点「启动」，允许 VPN 连接（系统弹窗点确定）。
- 电脑：打开「系统代理」；想全局生效再开「TUN 模式」（需要授权）。

**5. 验证**
- 打开目标网站（默认 bgacn.com），明显变快就成功了。没效果就重新跑一次优选换 IP，再重新生成导入一遍。

> 提示：只想加速目标站的话**不要开全局代理**，规则会自动让目标站走直连优选 IP，其它流量不受影响。



## 🤝 贡献与反馈

欢迎大家为本项目贡献力量！你可以通过以下方式参与：

- 💡 **提交 Issue**: 如果你在使用过程中遇到任何问题或有任何建议，欢迎提交 Issue。
- 🛠️ **提交 Pull Request**: 如果你有代码改进或新功能开发，欢迎提交 Pull Request。

## 📜 许可证

本项目使用 [MIT License](https://www.google.com/url?sa=E&q=LICENSE) 开源许可证。




## 🙏 感谢

感谢 [Cloudflare](https://www.google.com/url?sa=E&q=https%3A%2F%2Fwww.cloudflare.com%2F) 提供的全球 CDN 服务。

------



**希望这个工具能帮助你优化网络连接，享受更快速的网络体验！ 🎉**
