# NCM Decrypt 🎵

> 网易云音乐 `.ncm` 文件解密工具 — Web UI + CLI，支持多平台

一键解密网易云音乐下载的加密 `.ncm` 文件，还原为通用的 `mp3` / `flac` / `m4a` 等格式，自动写入歌曲元数据（标题、艺术家、专辑、封面）。

---

## ✨ 特性

- **Web UI 操作** — 浏览器打开即可拖拽/选择文件解密，无需记命令
- **批量并行解密** — 多 worker 并发处理，支持大文件
- **自动格式识别** — 自动检测 mp3 / flac / m4a / wav / ogg / aiff / ape
- **元数据写入** — 自动写入 ID3v2 (mp3) / Vorbis Comment (flac) 标签 + 封面图
- **解密记录追踪** — 已解密的文件自动跳过，避免重复处理
- **跨平台** — Linux / macOS / Windows / Termux，amd64 + arm64

---

## 🚀 快速开始

### 选项一：npm 安装（推荐）

```bash
npm install -g ncm-decrypt-cli
ncm-decrypt
```

### 选项二：直接下载二进制

从 [GitHub Releases](https://github.com/w32394045-dotcom/ncm-decrypt/releases) 下载对应平台的二进制文件：

| 平台 | 下载 |
|------|------|
| Linux x86_64 | `ncm-decrypt-v1.0.0-linux-amd64` |
| Linux ARM64 | `ncm-decrypt-v1.0.0-linux-arm64` |
| macOS Intel | `ncm-decrypt-v1.0.0-darwin-amd64` |
| macOS Apple Silicon | `ncm-decrypt-v1.0.0-darwin-arm64` |
| Windows x86_64 | `ncm-decrypt-v1.0.0-windows-amd64.exe` |
| Windows ARM64 | `ncm-decrypt-v1.0.0-windows-arm64.exe` |
| Termux (Android) | `ncm-decrypt-v1.0.0-termux-arm64` |

```bash
# Linux / macOS
chmod +x ncm-decrypt-v1.0.0-linux-amd64
./ncm-decrypt-v1.0.0-linux-amd64

# Windows
ncm-decrypt-v1.0.0-windows-amd64.exe
```

### 选项三：源码编译

```bash
git clone https://github.com/w32394045-dotcom/ncm-decrypt.git
cd ncm-decrypt
go build -ldflags="-s -w" -o ncm-decrypt .
./ncm-decrypt
```

---

## 📖 使用说明

启动后浏览器打开 **http://localhost:8080** 即可看到 Web 界面。

### 命令行参数

```bash
./ncm-decrypt -port 8080 -dir ./ncm_files -output ./output -workers 4
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-port` | `8080` | Web 服务端口 |
| `-host` | `0.0.0.0` | 监听地址 |
| `-dir` | `.` | NCM 文件所在目录 |
| `-output` | `./output` | 解密文件输出目录 |
| `-workers` | `3` | 并行工作线程数 |

### 手机端使用

在 Termux 上运行后，同一 Wi-Fi 下的其他设备可以访问 `http://<手机IP>:8080`。

---

## 🏗️ 技术栈

- **语言**: Go 1.26
- **Web 前端**: 内嵌单页 HTML（零外部依赖）
- **加密**: AES-128-ECB + RC4（逆向网易云音乐加密方案）
- **元数据**: ID3v2.3 (mp3) / Vorbis Comment + Picture (flac)

---

## 📦 发布渠道

| 渠道 | 地址 |
|------|------|
| GitHub | https://github.com/w32394045-dotcom/ncm-decrypt |
| npm | https://www.npmjs.com/package/ncm-decrypt-cli |

---

## 📄 License

MIT
