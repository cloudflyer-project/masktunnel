# MaskTunnel

一个智能代理，自动模拟不同浏览器的指纹以绑过检测系统。

## 简介

MaskTunnel 是一个 HTTP 代理，能够根据请求中的 User-Agent 头自动调整其"指纹"以匹配不同的浏览器（Chrome、Firefox、Safari 等）。这有助于绑过那些试图检测和阻止自动化流量的网站。

**核心特性：**
- **JA3/JA4 TLS 指纹模拟**：模拟真实浏览器的 JA3/JA4 TLS 指纹（Chrome、Firefox、Safari、Edge）
- **Akamai HTTP/2 指纹绕过**：复制浏览器特定的 HTTP/2 SETTINGS 和帧模式
- **动态适配**：根据 User-Agent 头自动选择正确的指纹
- **JavaScript 注入**：注入自定义代码以绕过客户端检测
- **零配置**：开箱即用，兼容任何 HTTP 客户端或浏览器
- **流式传输支持**：支持分块传输和 WebSocket 连接

## 安装

### Docker（推荐）

```bash
# 使用默认设置运行
docker run -p 8080:8080 jackzzs/masktunnel
```

### 预编译二进制文件

从 [Releases 页面](https://github.com/cloudflyer-project/masktunnel/releases) 下载预编译的二进制文件。

### 从源码构建

```bash
go run github.com/cloudflyer-project/masktunnel/cmd/masktunnel
```

## 使用方法

### 启动代理

在 8080 端口启动基本代理：
```bash
./masktunnel -port 8080
```

将浏览器或应用程序配置为使用 `http://localhost:8080` 作为 HTTP 代理。

### 常用选项

添加身份验证：
```bash
./masktunnel -username myuser -password mypass -port 8080
```

向网页注入自定义 JavaScript：
```bash
./masktunnel -payload "console.log('Hello from MaskTunnel!');" -port 8080
```

通过上游代理链式转发：
```bash
./masktunnel -upstream-proxy http://upstream:8080 -port 8080
```

### 测试指纹功能

测试不同的 User-Agent 是否产生不同的指纹：

**Chrome 指纹：**
```bash
curl -k -x http://localhost:8080 \
     -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
     https://tls.peet.ws/api/all
```

**Firefox 指纹：**
```bash
curl -k -x http://localhost:8080 \
     -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0" \
     https://tls.peet.ws/api/all
```

返回的指纹对于每个浏览器应该是不同的。

> **注意：** `-k` 参数用于跳过 SSL 证书验证。生产环境请参阅下方的[信任证书](#信任证书)部分。

## 命令行选项

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `-port` | 代理监听端口 | `8080` |
| `-addr` | 代理监听地址 | |
| `-username` | 代理身份验证用户名 | |
| `-password` | 代理身份验证密码 | |
| `-payload` | 注入到响应中的 JavaScript | |
| `-upstream-proxy` | 将请求转发到上游代理 | |
| `-user-agent` | 覆盖 User-Agent 头 | |
| `-cert` | TLS 证书文件 | `cert.pem` |
| `-key` | TLS 密钥文件 | `key.pem` |
| `-verbose` | 启用详细日志 | `0` |

## 信任证书

MaskTunnel 作为 MITM（中间人）代理来拦截和修改 HTTPS 流量。默认情况下，它会生成一个自签名证书，浏览器和工具不会信任该证书，因此需要在 curl 中使用 `-k` 参数或在其他客户端中使用类似选项。

如果您不希望破坏 HTTPS 的安全性（例如避免使用 `-k`），可以将生成的证书添加到系统的受信任证书存储中。

### 证书位置

证书文件位于：
- 默认：工作目录下的 `cert.pem`
- 自定义：通过 `-cert` 参数指定

### Windows

1. 双击 `cert.pem` 文件，或将其重命名为 `cert.crt` 后双击
2. 点击 **安装证书...**
3. 选择 **本地计算机**（需要管理员权限）或 **当前用户**
4. 选择 **将所有证书放入下列存储**
5. 点击 **浏览** 并选择 **受信任的根证书颁发机构**
6. 点击 **下一步**，然后点击 **完成**

或者使用 PowerShell（以管理员身份运行）：
```powershell
Import-Certificate -FilePath "cert.pem" -CertStoreLocation Cert:\LocalMachine\Root
```

### macOS

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain cert.pem
```

或通过钥匙串访问：
1. 打开 **钥匙串访问**（应用程序 → 实用工具）
2. 将 `cert.pem` 拖入 **系统** 钥匙串
3. 双击导入的证书
4. 展开 **信任**，将 **使用此证书时** 设置为 **始终信任**
5. 关闭窗口并输入密码确认

### Linux

**Debian/Ubuntu：**
```bash
sudo cp cert.pem /usr/local/share/ca-certificates/masktunnel.crt
sudo update-ca-certificates
```

**RHEL/CentOS/Fedora：**
```bash
sudo cp cert.pem /etc/pki/ca-trust/source/anchors/masktunnel.pem
sudo update-ca-trust
```

**Arch Linux：**
```bash
sudo cp cert.pem /etc/ca-certificates/trust-source/anchors/masktunnel.crt
sudo trust extract-compat
```

### 浏览器特定信任

部分浏览器维护自己的证书存储：

**Firefox：** 进入 设置 → 隐私与安全 → 证书 → 查看证书 → 证书颁发机构 → 导入

**Chrome（Linux）：** Chrome 在大多数平台上使用系统存储，但在 Linux 上可能需要：
```bash
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "MaskTunnel" -i cert.pem
```

## 致谢

MaskTunnel 基于以下优秀项目构建：
- [hazetunnel](https://github.com/daijro/hazetunnel) - User-Agent 检测和 payload 注入逻辑
- [azuretls-client](https://github.com/Noooste/azuretls-client) - 高级 TLS 和 HTTP/2 指纹模拟

## 许可证

本项目采用 GPLv3 许可证。
