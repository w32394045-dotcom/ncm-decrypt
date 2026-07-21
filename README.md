# NCM Decrypt 🎵

> Decrypt NetEase Cloud Music `.ncm` files — Web UI + CLI, cross-platform.
> 网易云音乐 `.ncm` 文件解密工具 — Web UI + CLI，支持多平台。

Decrypt encrypted `.ncm` files downloaded from NetEase Cloud Music into standard `mp3` / `flac` / `m4a` formats, with automatic metadata writing (title, artist, album, cover art).

一键解密网易云音乐下载的加密 `.ncm` 文件，还原为通用音频格式，自动写入歌曲元数据。

---

## ✨ Features / 特性

- **Web UI** — Open in browser, drag & drop to decrypt, no CLI needed / 浏览器打开即可操作
- **Batch parallel decryption** — Multi-worker concurrent processing / 多 worker 并发批量处理
- **Auto format detection** — mp3 / flac / m4a / wav / ogg / aiff / ape / 自动识别格式
- **Metadata & cover art** — ID3v2 (mp3), Vorbis Comment (flac) + cover / 自动写入标签和封面
- **Skip cache** — Already decrypted files are skipped / 已解密文件自动跳过
- **Cross-platform** — Linux / macOS / Windows / Termux, amd64 + arm64 / 跨平台

---

## 🚀 Quick Start / 快速开始

### Option 1: npm (Recommended / 推荐)

```bash
npm install -g ncm-decrypt-cli
ncm-decrypt
```

### Option 2: Download Binary / 下载二进制

Download from [GitHub Releases](https://github.com/w32394045-dotcom/ncm-decrypt/releases)：

| Platform / 平台 | File / 文件 |
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

### Option 3: Build from Source / 源码编译

```bash
git clone https://github.com/w32394045-dotcom/ncm-decrypt.git
cd ncm-decrypt
go build -ldflags="-s -w" -o ncm-decrypt .
./ncm-decrypt
```

---

## 📖 Usage / 使用说明

Open **http://localhost:8080** in your browser after starting.
启动后浏览器打开 **http://localhost:8080** 即可。

### CLI Flags / 命令行参数

```bash
./ncm-decrypt -port 8080 -dir ./ncm_files -output ./output -workers 4
```

| Flag / 参数 | Default / 默认值 | Description / 说明 |
|------|--------|------|
| `-port` | `8080` | Web server port / Web 服务端口 |
| `-host` | `0.0.0.0` | Bind address / 监听地址 |
| `-dir` | `.` | NCM file directory / NCM 文件目录 |
| `-output` | `./output` | Output directory / 输出目录 |
| `-workers` | `3` | Concurrent workers / 并行线程数 |

### Mobile Usage / 手机端使用

Run on Termux, then other devices on the same Wi-Fi can access `http://<phone-ip>:8080`.
在 Termux 上运行后，同一 Wi-Fi 的设备可访问 `http://<手机IP>:8080`。

---

## 🏗️ Tech Stack / 技术栈

- **Language**: Go 1.26
- **Frontend**: Embedded single-page HTML (zero external deps) / 内嵌单页 HTML（零外部依赖）
- **Crypto**: AES-128-ECB + RC4 (reverse-engineered NetEase scheme) / 逆向网易云加密方案
- **Metadata**: ID3v2.3 (mp3) / Vorbis Comment + Picture Block (flac)

---

## 📦 Distribution / 发布渠道

| Channel / 渠道 | URL / 地址 |
|------|------|
| GitHub | https://github.com/w32394045-dotcom/ncm-decrypt |
| npm | https://www.npmjs.com/package/ncm-decrypt-cli |

---

## 📄 License

MIT
