# AppTriage 应用排查工具

一个 Windows 桌面小工具，用来排查并清理“被捆绑软件（如 WPS、2345、鲁大师、360）搞乱的电脑”：
默认打开方式被抢占、开机自启动和后台服务、计划任务、卸载残留、隐藏的可执行文件、浏览器被篡改的启动页。
界面全部为简体中文，并内置一个 AI 助手（DeepSeek），可以解释扫描结果、回答“开机为什么慢”之类的问题。

## 功能

- **扫描**：六类检查——已安装程序、文件默认打开方式（图片 / PDF / Office）、开机自启动（Run 键、启动文件夹、服务、计划任务、Winlogon / IFEO）、卸载残留（文件夹与注册表）、隐藏的可执行文件、浏览器劫持（快捷方式被附加网址、主页被改）。
- **AI 助手**：只能调用只读的查询工具，并通过“建议修复”提出方案；AI 永远不能自己执行任何操作。
- **修复记录**：每次修复都有记录，可以一键撤销。

## 安全模型

1. **先确认再执行**：任何系统改动都必须由你在“确认修复”对话框中点击确认；高风险项（例如禁用服务）会再单独确认一次。AI 只能提出建议。
2. **先备份再修改**：修改前会尝试创建系统还原点，并备份相关注册表（`reg export`）、原有的值；失败时会提示。
3. **隔离而非删除**：文件和文件夹不会被删除，只会移动到隔离区 `%APPDATA%\AppTriage\sessions\<时间>\quarantine`。
4. **可撤销**：在“修复记录”页选择一次修复，点击“撤销此次修复”，只会按相反顺序撤销真正成功执行的步骤。不可撤销的操作（例如运行卸载程序）会在确认时标明。
5. **隐私**：发送给 AI 的只有名称、路径、注册表项、签名 / 发布者等元数据；路径中的用户名会替换为 `%USER%`；单次工具结果最多 12000 字符。

## 设置 DeepSeek API Key

1. 到 DeepSeek 开放平台申请一个 API Key。
2. 打开程序，进入“设置”页，填入 API Key（Base URL 默认 `https://api.deepseek.com`，模型默认 `deepseek-chat`，都可以修改）。
3. 点击“测试连接”确认可用，再点击“保存”。

Key 保存在 `%APPDATA%\AppTriage\config.json`，使用 Windows DPAPI（当前用户）加密，不以明文存放。不设置 Key 时，扫描和修复照常可用，只是 AI 助手不可用。

## 构建 Windows 可执行文件

`AppTriage.exe` **必须在 Windows 上构建**（PyInstaller 不能跨平台打包）。有两种方式：

- **本机构建**：安装 [uv](https://docs.astral.sh/uv/) 后，在仓库根目录运行 `build.bat`，产物为 `dist\AppTriage.exe`。程序带有管理员清单，双击时会弹出 UAC 提示。
- **GitHub Actions**：推送代码或手动触发 `build` 工作流（`.github/workflows/build.yml`，运行在 `windows-latest`）。它会先运行测试（其中 `tests/test_windows_smoke.py` 只在 Windows 上执行），再构建，并把 `dist/AppTriage.exe` 作为名为 `AppTriage` 的 artifact 上传，可在 Actions 页面下载。

## 开发与演示模式

需要 Python 3.12 和 [uv](https://docs.astral.sh/uv/)：

```bash
uv sync --group dev
uv run pytest -q                 # 运行测试（Qt 测试自动使用 offscreen）
uv run python -m app_triage --demo
```

`--demo`（在非 Windows 系统上会自动启用）使用内置的模拟系统，场景是“WPS 已卸载但痕迹仍在”：`.jpg` / `.png` / `.pdf` 默认打开方式被占用（其中 `.jpg` 的 UserChoice 被拒绝访问）、WPS 的 Run 自启项、`wpscloudsvr` 自动启动服务、`\WPS\WpsUpdateTask` 计划任务、`AppData` 下的 Kingsoft 残留目录与注册表项、`ProgramData` 中隐藏的未签名程序、带有 `https://www.2345.com` 的 Edge 快捷方式，另有一个仍已安装的“2345看图王”。演示模式不会读取或修改真实系统；配置保存在 `~/.apptriage/config.json`（不加密），修复记录保存在 `~/.apptriage/sessions`。

在 Windows 上从源码运行（`uv run python -m app_triage`）时若不是管理员身份，会提示修复服务、计划任务、HKLM 等需要管理员权限。

## 已知限制：默认应用的最后一步需要你手动完成

Windows 对“默认应用”的选择做了保护（UserChoice 哈希校验以及较新版本中的 UCPD 驱动），任何程序都不能直接替你指定默认应用。因此，AppTriage 清除 WPS 对 `.jpg`、`.png`、`.pdf` 等类型的占用后，会自动打开系统“设置 → 默认应用”页面，请在那里为对应的文件类型自己选择想用的程序（例如图片选择“照片”），然后重新扫描确认。

## 在 Windows 虚拟机中的验证步骤

在虚拟机快照上验证：构建（或下载 artifact）→ 安装 WPS → 运行 `AppTriage.exe`（UAC 提示）→ 扫描应列出被占用的 `.jpg` / `.png` 以及 WPS 的 Run 项、服务和计划任务 → 修复后会打开默认应用设置，选择“照片” → 重新扫描应为干净 → 在“修复记录”中撤销可恢复之前的状态 → 卸载 WPS 后重新扫描应列出残留 → 在“AI 助手”中提问“开机很慢”，AI 会调用自启动查询，且只提出修复建议。
