#!/bin/bash
# NCM Decrypt — Installation Script / 安装脚本
# Supports: Linux, Termux (Android), macOS, Windows (MSYS2/Git Bash/Cygwin)
set -e

# Detect OS
OS="$(uname -s)"
IS_TERMUX=false
IS_WINDOWS=false
PACKAGE_MANAGER=""

if [ -d "/data/data/com.termux" ] || [ -n "$TERMUX_VERSION" ]; then
    IS_TERMUX=true
fi

case "$OS" in
    Linux*)     IS_LINUX=true ;;
    Darwin*)    IS_MACOS=true ;;
    MINGW*|MSYS*|CYGWIN*) IS_WINDOWS=true ;;
    *)          IS_OTHER=true ;;
esac

# Language detection / 语言检测
if echo "${LANG:-en}" | grep -qi "zh"; then
    LANG_CN=true
else
    LANG_CN=false
fi

echo "================================"
$LANG_CN && echo "  NCM Decrypt 安装脚本" || echo "  NCM Decrypt Installer"
$LANG_CN && echo "  支持: Linux / Termux / macOS / Windows" || echo "  Supports: Linux / Termux / macOS / Windows"
echo "================================"

# 1. Check/Install Go
if ! command -v go &>/dev/null; then
    echo ""
    if $IS_TERMUX; then
        if $LANG_CN; then
            echo "[1/3] 安装 Go (pkg install golang)..."
        else
            echo "[1/3] Installing Go (pkg install golang)..."
        fi
        pkg update -y
        pkg install golang -y
    elif $IS_MACOS; then
        if $LANG_CN; then
            echo "[1/3] 需要安装 Go。请运行: brew install go"
        else
            echo "[1/3] Go is required. Run: brew install go"
        fi
        echo ""
        echo "  或者从 https://golang.org/dl/ 下载安装"
        exit 1
    elif $IS_WINDOWS; then
        if $LANG_CN; then
            echo "[1/3] 需要安装 Go。请运行: winget install GoLang.Go"
            echo "  或从 https://golang.org/dl/ 下载安装"
        else
            echo "[1/3] Go is required. Run: winget install GoLang.Go"
            echo "  Or download from https://golang.org/dl/"
        fi
        exit 1
    else
        if $LANG_CN; then
            echo "[1/3] 安装 Go (apt install golang-go)..."
        else
            echo "[1/3] Installing Go (apt install golang-go)..."
        fi
        # Try various package managers
        if command -v apt &>/dev/null; then
            apt update -y
            apt install golang-go -y
        elif command -v pacman &>/dev/null; then
            pacman -S --noconfirm go
        elif command -v dnf &>/dev/null; then
            dnf install -y golang
        elif command -v apk &>/dev/null; then
            apk add go
        else
            if $LANG_CN; then
                echo "  无法自动安装 Go，请手动安装: https://golang.org/dl/"
            else
                echo "  Cannot auto-install Go. Please install manually: https://golang.org/dl/"
            fi
            exit 1
        fi
    fi
else
    if $LANG_CN; then
        echo "[1/3] Go 已安装 ($(go version))"
    else
        echo "[1/3] Go is installed ($(go version))"
    fi
fi

# 2. Compile
if $LANG_CN; then
    echo "[2/3] 编译中..."
else
    echo "[2/3] Compiling..."
fi
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Set output binary name per platform
OUTPUT="ncm-decrypt"
if $IS_WINDOWS; then
    OUTPUT="ncm-decrypt.exe"
fi

go build -ldflags="-s -w" -o "$OUTPUT" .

# Also create a cross-platform build helper
if $LANG_CN; then
    echo "  提示: 如需交叉编译其他平台，使用:"
    echo "    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o ncm-decrypt.exe ."
    echo "    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ncm-decrypt ."
else
    echo "  Note: For cross-compilation, use:"
    echo "    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o ncm-decrypt.exe ."
    echo "    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ncm-decrypt ."
fi

# 3. Done
if $LANG_CN; then
    echo "[3/3] 完成!"
    echo ""
    echo "================================"
    echo ""
    echo "  ✅ 编译成功: $OUTPUT"
    echo ""
    echo "  用法:"
    echo "    ./$OUTPUT                            # 本地模式 (默认)"
    echo "    ./$OUTPUT -mode 0                    # 本地模式（指定目录）"
    echo "    ./$OUTPUT -mode 1                    # 服务器部署模式（需登录）"
    echo ""
    echo "  平台相关说明:"
    if $IS_TERMUX; then
        echo "  📱 Termux 运行:"
        echo "     ./$OUTPUT -dir ~/storage/music"
    fi
    if $IS_WINDOWS; then
        echo "  🪟 Windows 运行:"
        echo "     .\\$OUTPUT"
    fi
    echo ""
    echo "  访问: http://localhost:8080"
    echo ""
    echo "================================"
else
    echo "[3/3] Done!"
    echo ""
    echo "================================"
    echo ""
    echo "  ✅ Build successful: $OUTPUT"
    echo ""
    echo "  Usage:"
    echo "    ./$OUTPUT                            # Local mode (default)"
    echo "    ./$OUTPUT -mode 0                    # Local mode (custom dir)"
    echo "    ./$OUTPUT -mode 1                    # Server mode (login required)"
    echo ""
    if $IS_TERMUX; then
        echo "  📱 Termux:"
        echo "     ./$OUTPUT -dir ~/storage/music"
    fi
    if $IS_WINDOWS; then
        echo "  🪟 Windows:"
        echo "     .\\$OUTPUT"
    fi
    echo ""
    echo "  Open: http://localhost:8080"
    echo ""
    echo "================================"
fi
