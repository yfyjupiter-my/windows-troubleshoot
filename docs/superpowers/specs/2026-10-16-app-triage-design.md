# AI Windows 应用排查工具 — 设计与实施方案

## Context（为什么做）
用户的电脑被捆绑安装了 WPS，图片默认打开方式被抢成 "WPS 图片"，还伴随自启动、后台服务等流氓行为。现有工具要么只能卸载、清不干净，要么不解释发生了什么。目标：一个**只给用户本人用**的 Windows 桌面工具（单个 .exe），扫描残留/隐藏/流氓项，由 **DeepSeek AI** 用中文解释，并能根据用户描述（如"开机很慢"）自己决定去查哪里；**所有修复必须经用户逐项确认**，且可撤回。

项目目录 `/home/ubuntu/Documents/myClaude/it-support` 当前为空，从零开始。

## 目标 / 非目标 / 反目标
- 目标：查出 WPS 这类捆绑软件留下的一切痕迹并恢复系统原状；AI 解释 + 对话排查；单 exe。
- 非目标：杀毒/病毒特征库、实时防护、多用户/分发/售卖、云端账号。
- 反目标（技术上能跑也算失败）：未经确认改系统；删除后无法恢复；把用户文件内容上传给 AI；误删系统/正常软件组件。

## 已定（用户决定）
- 流程：扫描 → AI 解释 → 用户勾选确认 → 执行修复。
- 支持 AI 对话：用户描述问题，AI 调用**只读**扫描工具自行排查；修复依然只能"提议"，由用户确认。
- AI 服务：DeepSeek API，仅本人使用。
- 技术选型交给我定。

## 我的决定（可推翻）
- **Python 3.12 + PySide6 (Qt) 桌面界面 + PyInstaller 打包单 exe**（`--onefile --uac-admin`，启动即请求管理员权限）。
- AI 接入：`openai` SDK，`base_url=https://api.deepseek.com`，模型名在设置里可改（默认 `deepseek-chat`，需支持 function calling）。
- API key 存 `%APPDATA%\AppTriage\config.json`，用 Windows DPAPI（`win32crypt`）加密；首次启动在设置页填写。
- 发给 AI 的只有元数据（程序名、路径、注册表键、签名、发布者），路径中的用户名替换为 `%USER%`。
- 安全网：每次修复前自动 ① `reg export` 涉及的键 ② 尝试创建系统还原点 ③ 文件/文件夹**移入隔离区**而非删除。所有操作写入撤销日志，界面提供"撤销本次修复"。

## 架构
```
app_triage/
  main.py                 # 启动、管理员检查
  ui/                     # PySide6：扫描页、发现列表(勾选)、AI 对话页、设置页、历史/撤销页
  scanners/               # 每个扫描器返回 Finding(id, category, title, evidence, risk, suggested_actions)
    installed.py          # 卸载注册表 HKLM/HKCU/WOW6432Node
    leftovers.py          # Program Files / ProgramData / AppData 中无对应已装程序的目录；孤立的 HKCU/HKLM\Software 键
    autoruns.py           # Run/RunOnce、启动文件夹、服务、计划任务、Winlogon、IFEO
    file_assoc.py         # FileExts\<ext>\UserChoice / OpenWithProgids / ProgID，对比"谁抢了关联"
    browser.py            # 快捷方式参数劫持、Edge/Chrome 主页与搜索引擎
    hidden.py             # 用户可写目录下 hidden+system 属性的可执行文件、ADS
    signature.py          # Authenticode 签名/发布者（PowerShell Get-AuthenticodeSignature）
  actions/                # 修复动作：每个有 preview()、backup()、apply()、undo()
  ai/
    client.py             # DeepSeek 调用
    tools.py              # 暴露给 AI 的工具：只读扫描器 + propose_fix（只入队，不执行）
    agent.py              # 工具调用循环，限制最大轮数
  safety/                 # 备份、还原点、隔离区、撤销日志、路径脱敏
  platform/               # Windows 适配层（winreg/psutil/subprocess）；Linux 上用假数据实现，便于测试
tests/
build.bat + .github/workflows/build.yml   # Windows 上打包
```
核心逻辑（Finding、AI 工具循环、动作队列、撤销日志）不直接调 Windows API，经 `platform/` 适配层，因此能在 Linux 上用假数据单测。

## 关键难点（WPS 场景）
- Win8+ 的 `UserChoice` 带哈希校验，**不能直接写入**；Win11 还有 UCPD 驱动保护部分关联。做法：删除被劫持的 `UserChoice` 键（WPS 有时会加拒绝 ACL，需先取回权限）、清理 WPS 写入的 `OpenWithProgids`/ProgID，然后打开 `ms-settings:defaultapps` 引导用户选回"照片"，再复扫确认。
- 已知流氓软件（WPS、2345、鲁大师、360 系等）的特征做成内置规则表，AI 解释时作为参考，但不作为唯一判断依据。
- 不删 Windows 自带和有微软签名的组件；高风险项（服务、驱动、System32 下文件）在界面上标红并二次确认。

## 实施顺序
1. 项目骨架 + platform 适配层 + Finding 模型 + 测试框架。
2. 扫描器：installed → file_assoc → autoruns → leftovers → hidden/browser/signature。
3. safety：备份、隔离区、撤销日志。
4. actions：恢复文件关联、禁用自启/服务/计划任务、移除残留。
5. AI：client、tools、agent 循环（只读 + propose_fix）。
6. UI：扫描页 → 发现列表勾选 → AI 对话 → 设置 → 历史/撤销。
7. 打包：`build.bat` + GitHub Actions（windows-latest）产出 exe。

## 验证
- Linux 上：`pytest` 跑假数据测试（扫描器解析、AI 工具循环用模拟 DeepSeek 响应、动作的 backup/apply/undo 往返）。
- 在 Windows（最好是虚拟机/快照）上：装 WPS → 运行 exe → 确认能查出图片关联被抢、自启、服务、计划任务 → 勾选修复 → 图片恢复用"照片"打开 → 执行"撤销"后状态回到修复前 → 卸载 WPS 后再扫，能列出残留。
- AI 对话：输入"开机很慢"，确认 AI 调用了 autoruns/服务扫描并给出解释，修复只出现在待确认列表中。

## 注意
- 当前开发环境是 Linux，**无法直接生成 .exe**；最终打包需在你的 Windows 电脑上运行 `build.bat`，或推到 GitHub 由 Actions 自动打包。
