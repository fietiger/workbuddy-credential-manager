# WorkBuddy Credential Manager

本地 WorkBuddy / CodeBuddy 凭证管理器。纯本地运行：无代理、无中继、不上传任何数据。

基于 Tauri 2 + Rust 构建的桌面应用，用来收集本机散落的 WorkBuddy 登录凭证、统一管理多个账号，并一键把选定账号切入 WorkBuddy 桌面端（国内 / 国际）与 CodeBuddy CLI 登录。

## 功能

- **多账号管理**：添加、删除、备注多个账号；卡片展示站点（国内版 / 国际版）、来源、凭证掩码、有效期，以及该账号正被哪些客户端使用
- **OAuth 登录**：内置 WorkBuddy 插件授权流程（`/v2/plugin/auth/state` → 浏览器登录 → 轮询取 token），支持国内版（workbuddy.cn）与国际版（workbuddy.ai）。链接不会自动打开，由你复制到任意浏览器完成登录；本页面每 5 秒轮询一次结果，会话 30 分钟有效。重复登录同一账号会更新库内凭证而不是报错
- **导入 refresh token**：已有 refresh token 时可直接导入生成账号；若同时粘贴 access token（JWT），会自动识别邮箱与过期时间
- **一键导入本地账号**：扫描 WorkBuddy 桌面端认证目录里的**所有** `workbuddy-desktop*.info` 文件（含客户端与切换工具留下的历史登录备份）以及 CodeBuddy CLI 的 `settings.json`，按 uid 去重后一键收进管理器；已在库中的账号仅在磁盘上的凭证更新（或磁盘上是明文、库内是加密信封）时更新
- **一键切换登录**：每个账号可分别切入三个客户端——WorkBuddy 桌面端（国内）、WorkBuddy AI 桌面端（国际）、CodeBuddy CLI；各客户端独立保存当前账号、互不影响。写入前自动备份原文件（`.wcm-bak-时间戳`），写入采用临时文件+替换，写后立即回读校验：客户端在运行中把内存状态写回、吞掉这次切换时，会直接报错而不是假装成功
- **凭证刷新**：读取或切换时若 access token 过期（提前 60 秒判定），自动用 refresh token 经 `/v2/plugin/auth/token/refresh` 续期；账号卡上也有手动刷新按钮
- **导出 / 导入备份**：一键导出全部账号为 JSON（含加密信封原文，跨机迁移后仍可切换桌面端）；导入支持本应用自己的导出格式，重复账号自动跳过、更新的凭证自动合入
- **文件日志**：结构化日志写入应用数据目录，界面内可直接打开日志目录

## 数据存储

所有数据只存在本机应用数据目录下的 `workbuddy-credential-manager/` 文件夹：

| 内容 | 文件 |
| --- | --- |
| 账号索引 | `accounts.json` |
| 单个账号凭证 | `accounts/<id>.json` |
| 日志 | `logs/app.log` |

各平台应用数据目录：

- Windows：`%APPDATA%\workbuddy-credential-manager\`
- macOS：`~/Library/Application Support/workbuddy-credential-manager/`
- Linux：`~/.local/share/workbuddy-credential-manager/`

## 它读写哪些本机文件

| 客户端 | 文件 | 行为 |
| --- | --- | --- |
| WorkBuddy 桌面端（国内） | `%LOCALAPPDATA%\CodeBuddyExtension\Data\Public\auth\workbuddy-desktop.info` | 读取 + 切换写入 |
| WorkBuddy AI 桌面端（国际） | 同目录 `workbuddy-desktop-ai.info` | 读取 + 切换写入 |
| CodeBuddy CLI | `~/.codebuddy/settings.json` | 读取 + 切换写入 |

> WorkBuddy 桌面端的凭证可能以 `$wbEncrypted` 信封加密存储（密钥在本机凭据管理器中）。本应用**不解密**：信封原样保存、原样写回，因此加密账号在本机上照常切换桌面端；但无法写入 CodeBuddy CLI（CLI 需要明文 JWT）、也无法用它刷新。明文凭证（OAuth 登录、CLI 抓取的 JWT）则三端通用。
>
> ⚠️ 切换桌面端账号前建议先完全退出 WorkBuddy 客户端——运行中的客户端可能把内存里的登录态写回、覆盖刚写入的凭证（应用回读校验会捕获这种情况并报错）。
>
> ⚠️ 账号凭证以明文/信封 JSON 保存在本地，请注意本机账户与磁盘安全；导出的备份文件包含 refresh token，不要分享给他人。

## 构建

环境要求：Rust ≥ 1.77；Linux 还需要 webkit2gtk 等系统依赖。

```bash
# Linux 先装系统依赖
sudo apt-get install -y libwebkit2gtk-4.1-dev libayatana-appindicator3-dev \
  librsvg2-dev patchelf libssl-dev

# 构建可独立运行的 release 可执行文件（必须用 Tauri CLI）
npx -y @tauri-apps/cli@^2 build --no-bundle

# 注意：不要直接 cargo build —— 产出的是开发模式二进制，
# 运行时会去连接 localhost:1420 的开发服务器，无法独立使用。
```

GitHub Actions（`.github/workflows/build.yml`）会在 push 时自动构建 Windows / macOS / Linux 三平台产物；打 `v*` tag 时自动发布 Release。

## 开发

```bash
cargo fmt --all --manifest-path src-tauri/Cargo.toml
cargo clippy --all-targets --manifest-path src-tauri/Cargo.toml
cargo test --manifest-path src-tauri/Cargo.toml
```

调试日志：设置环境变量 `WB_LOG_DEBUG=1` 后再启动应用，可输出 debug 级别日志。

## 项目结构

```
ui/                  单页前端（index.html）
src-tauri/
  src/
    commands/        Tauri IPC 命令（账号、OAuth、本地导入、切换、导入导出）
    models/          Account / CredentialValue 数据模型
    modules/         account_store 本地存储、wb_auth 授权与刷新、
                     client_sync 客户端切换、local_import 本地扫描、logger 文件日志
```

## 许可证

MIT
