# XeApi Aegis MITM

这是一个用于本地逆向和调试网易云音乐 `/xeapi` Aegis 加密流量和传统 `/eapi` 加密流量的 MITM 工具。它内嵌 mitmproxy，并提供一个 TUI 界面来查看命中的请求、响应、解密后的 payload、原文和 session key 信息。

请只在你自己的设备、账号和授权网络环境中使用。抓包结果、证书、私钥、cookie、日志都可能包含敏感信息，不要提交或分享。

## 你需要准备什么

- Windows PowerShell
- Python 3.11 或更新版本
- `uv`
- 一台和电脑在同一网络下的 Android 设备或模拟器
- 设备已信任用于抓包的根证书

第一次进入项目目录后执行：

```powershell
uv sync
uv run aegis-mitm-selftest
```

如果看到下面输出，说明基础加解密链路正常：

```text
aegis mitm selftest ok
```

## 启动工具

在项目根目录运行：

```powershell
uv run aegis-mitm-tui
```

默认配置是：

- 监听地址：`0.0.0.0`
- 监听端口：`8080`
- 上游代理：`http://127.0.0.1:9370`
- 忽略上游 TLS 证书问题
- Aegis 公钥有效期：10 分钟
- 运行产物目录：`tool/runs/`

也可以显式指定：

```powershell
uv run aegis-mitm-tui --listen-host 0.0.0.0 --listen-port 8080 --upstream-proxy http://127.0.0.1:9370
```

如果你的上游是 SOCKS5，也可以这样：

```powershell
uv run aegis-mitm-tui --upstream-proxy socks5://127.0.0.1:9370
```

## 配置手机代理

1. 确认手机和电脑在同一局域网。
2. 查看电脑的局域网 IP。
3. 在手机 Wi-Fi 代理中填入：
   - 主机：电脑局域网 IP
   - 端口：`8080`
4. 打开目标 App，让它发起 `/xeapi` 或 `/eapi` 请求。

命中的请求会出现在 TUI 左侧列表。点选请求后，右侧可以查看：

- 请求和响应摘要
- Request Body
- Response Body
- 原始请求和响应内容
- session key 等调试信息

每个详情页顶部都有复制按钮，可以把 URL、Headers、Body、Raw Events、session 信息等复制到剪贴板。

底部日志可以折叠，主要用于看运行状态和失败原因。

## 证书和私钥

工具默认会尝试加载：

```text
tool/capture-ca.pem
```

这个文件应包含 mitmproxy 可用的 CA 证书和私钥。你的设备必须信任对应根证书，否则 HTTPS 会报类似 `ERR_CERT_AUTHORITY_INVALID` 的错误。

这些文件是敏感文件，已经在 `.gitignore` 中忽略：

```text
tool/capture-ca.pem
tool/capture-cert.pem
tool/capture-key.pem
tool/proxy-server-x25519.key
```

## 它是怎么工作的

对于 `/xeapi`，工具会拦截 Aegis 公钥接口：

```text
/gorilla/anti/crawler/security/key/get
```

然后把服务端返回的 Aegis 公钥替换成本地代理公钥。这样代理就可以解开请求里的 `S`，解密 `B`，展示明文请求，再用真实服务端公钥重新封装并放行。

对于 `/eapi`，工具会解开表单中的 `params` 字段，校验 envelope 里的 MD5，并尝试用 legacy eapi response key 解密响应。`/eapi` 请求不会被改写，只做观察和展示。

没有命中的请求不会处理，会原样放行。

## 常用参数

```powershell
uv run aegis-mitm-tui --response-mode auto
uv run aegis-mitm-tui --ssl-verify-upstream
uv run aegis-mitm-tui --public-key-ttl-seconds 600
uv run aegis-mitm-tui --no-force-key-refresh-on-miss
```

`--response-mode` 可选：

- `auto`：自动尝试 legacy 和 session/request key
- `legacy`：只尝试 legacy eapi response key
- `session`：只尝试 session/request key

默认情况下，如果 `/xeapi` 流量早于 `key/get` 出现，工具会注入一次 `x-ud-sts=10000`，提示客户端刷新 Aegis 公钥。

## 文件说明

```text
aegis_xeapi.py             Aegis 加解密核心实现和命令行辅助
mitm_aegis_xeapi.py        早期 standalone MITM 辅助脚本
tool/aegis_tui.py          Textual TUI 和内嵌 mitmproxy 启动器
tool/aegis_mitm_addon.py   mitmproxy addon
tool/aegis_mitm_core.py    请求解密、响应解密、公钥替换等共享逻辑
tool/aegis_mitm_selftest.py 离线自测
tool/runs/events.jsonl     TUI 读取的运行事件
tool/runs/dumps/           请求和响应 dump
```

## 调试建议

如果 TUI 没有请求：

- 确认手机代理指向电脑 IP 和 `8080`
- 确认证书已经被设备信任
- 确认 App 真的发起了 `/xeapi` 或 `/eapi` 请求
- 看底部日志是否出现 `real public key missing; wait for key/get`

如果响应无法解密：

- 查看该请求详情里的 session 信息
- 查看底部日志里的 `response-decrypt-failed`
- 检查 `tool/runs/dumps/` 中对应的 raw dump

## 不要提交的东西

下面这些通常包含账号、设备、证书、cookie、session 或抓包内容：

- `tool/runs/`
- `*.har`
- `*.log`
- `*.pem`
- `*.key`
- `.venv/`
- `__pycache__/`
- `*.egg-info/`

它们已经被 `.gitignore` 忽略。提交前可以执行：

```powershell
git status --ignored
```

确认敏感文件只出现在 ignored 区域。
