<p align="right">
  <a href="README.zh-CN.md">🇨🇳 中文</a>
</p>

<h1 align="center">🎵 NCM Decrypt</h1>

<p align="center">
  <em>Decrypt NetEase Cloud Music .ncm files — Web UI + CLI, cross-platform.</em>
</p>

<p align="center">
  <a href="https://github.com/w32394045-dotcom/ncm-decrypt/releases">
    <img src="https://img.shields.io/github/v/release/w32394045-dotcom/ncm-decrypt" alt="Release">
  </a>
  <a href="https://www.npmjs.com/package/ncm-decrypt-cli">
    <img src="https://img.shields.io/npm/v/ncm-decrypt-cli" alt="npm">
  </a>
  <a href="https://github.com/w32394045-dotcom/ncm-decrypt/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/w32394045-dotcom/ncm-decrypt" alt="License">
  </a>
</p>

---

Decrypt `.ncm` files downloaded from NetEase Cloud Music into standard `mp3` / `flac` / `m4a` formats, with automatic metadata writing (title, artist, album, cover art).

## ✨ Features

- **Web UI** — Open in browser, drag & drop to decrypt
- **Batch parallel** — Multi-worker concurrent processing
- **Auto detect** — mp3 / flac / m4a / wav / ogg / aiff / ape
- **Metadata & cover** — ID3v2 (mp3), Vorbis Comment (flac), cover art
- **Skip cache** — Already decrypted files are skipped automatically
- **Cross-platform** — Linux / macOS / Windows / Termux, amd64 + arm64

## 🚀 Quick Start

### Option 1: npm (Recommended)

```bash
npm install -g ncm-decrypt-cli
ncm-decrypt
```

### Option 2: Download Binary

Download from [GitHub Releases](https://github.com/w32394045-dotcom/ncm-decrypt/releases):

| Platform | File |
|----------|------|
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

### Option 3: Build from Source

```bash
git clone https://github.com/w32394045-dotcom/ncm-decrypt.git
cd ncm-decrypt
go build -ldflags="-s -w" -o ncm-decrypt .
./ncm-decrypt
```

## 📖 Usage

Open **http://localhost:8080** in your browser after starting.

### CLI Flags

```bash
./ncm-decrypt -port 8080 -dir ./ncm_files -output ./output -workers 4
```

| Flag | Default | Description |
|------|---------|-------------|
| `-port` | `8080` | Web server port |
| `-host` | `0.0.0.0` | Bind address |
| `-dir` | `.` | NCM file directory |
| `-output` | `./output` | Output directory |
| `-workers` | `3` | Concurrent workers |

### Mobile

Run on Termux, then other devices on the same Wi-Fi can access `http://<phone-ip>:8080`.

## 🏗️ Tech Stack

- **Language**: Go 1.26
- **Frontend**: Embedded single-page HTML (zero external dependencies)
- **Crypto**: AES-128-ECB + RC4 (reverse-engineered NetEase scheme)
- **Metadata**: ID3v2.3 (mp3) / Vorbis Comment + Picture Block (flac)

## 📦 Distribution

| Channel | URL |
|---------|-----|
| GitHub | https://github.com/w32394045-dotcom/ncm-decrypt |
| npm | https://www.npmjs.com/package/ncm-decrypt-cli |

## 📄 License

MIT
