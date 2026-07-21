#!/bin/bash
# NCM Decrypt — Build from source / 源码编译安装脚本
set -e

echo "================================"
echo "  NCM Decrypt"
echo "  Build from source / 源码编译"
echo "================================"

# 1. Check/Install Go
if ! command -v go &>/dev/null; then
    echo ""
    echo "[1/3] Installing Go... / 安装 Go..."
    echo ""
    if command -v pkg &>/dev/null; then
        # Termux
        pkg update -y
        pkg install golang -y
    elif command -v apt &>/dev/null; then
        sudo apt update -y
        sudo apt install golang-go -y
    elif command -v brew &>/dev/null; then
        brew install go
    else
        echo "Please install Go first: https://go.dev/dl/"
        echo "请先安装 Go: https://go.dev/dl/"
        exit 1
    fi
else
    echo "[1/3] Go already installed / Go 已安装 ($(go version))"
fi

# 2. Compile
echo "[2/3] 编译..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
go build -ldflags="-s -w" -o ncm-decrypt .

# 3. Done
echo "[3/3] 完成!"
echo ""
echo "================================"
echo ""
echo "  ✅ 编译成功!"
echo ""
echo "  用法:"
echo "    ./ncm-decrypt                          # 默认监听 :8080"
echo "    ./ncm-decrypt -port 8080 -dir ~/Music  # 指定目录"
echo "    ./ncm-decrypt -output ./output -workers 4"
echo ""
echo "  运行后浏览器打开:"
echo "    http://localhost:8080"
echo ""
echo "  📱 在手机上用同一 Wi-Fi 的其他设备访问:"
echo "     http://<手机IP>:8080"
echo ""
echo "================================"
