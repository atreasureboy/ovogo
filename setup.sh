#!/bin/bash
# ================================================================
#  Ovogo 一键环境配置脚本 (macOS / Linux)
#
#  功能：
#    1. 检测 Node.js
#    2. 安装 npm 依赖
#    3. 编译 TypeScript
#    4. 将 ovogogogo 添加为全局命令 ovogo
#    5. 验证安装
# ================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo "============================================="
echo "  Ovogo 环境配置 — macOS / Linux"
echo "============================================="
echo ""

# ── 1. 检查 Node.js ──────────────────────────
if ! command -v node &> /dev/null; then
    echo -e "${RED}[ERROR] Node.js 未安装！${NC}"
    echo "请先安装 Node.js:"
    echo "  macOS: brew install node"
    echo "  Ubuntu/Debian: curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash - && sudo apt install -y nodejs"
    echo "  CentOS/RHEL: curl -fsSL https://rpm.nodesource.com/setup_lts.x | sudo bash - && sudo yum install -y nodejs"
    exit 1
fi

NODE_VER=$(node -v)
echo -e "${GREEN}[OK]${NC} Node.js 已安装: $NODE_VER"

# ── 2. 检查 npm ─────────────────────────────
if ! command -v npm &> /dev/null; then
    echo -e "${RED}[ERROR] npm 未找到！${NC}"
    exit 1
fi

NPM_VER=$(npm -v)
echo -e "${GREEN}[OK]${NC} npm 已安装: $NPM_VER"

# ── 3. 确定项目根目录 ────────────────────────
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

# ── 4. 安装依赖 ─────────────────────────────
echo ""
echo -e "${BLUE}[1/3]${NC} 安装 npm 依赖..."
npm install
echo -e "${GREEN}[OK]${NC} 依赖安装完成"

# ── 5. 编译 TypeScript ──────────────────────
echo ""
echo -e "${BLUE}[2/3]${NC} 编译 TypeScript..."
npm run build
echo -e "${GREEN}[OK]${NC} 编译完成"

# ── 6. 添加全局命令 ovogo ──────────────────
echo ""
echo -e "${BLUE}[3/3]${NC} 添加全局命令 \"ovogo\"..."

BIN_FILE="$PROJECT_DIR/dist/bin/ovogogogo.js"
if [ ! -f "$BIN_FILE" ]; then
    echo -e "${RED}[ERROR] 编译输出未找到: $BIN_FILE${NC}"
    exit 1
fi

GLOBAL_PREFIX=$(npm prefix -g)
GLOBAL_BIN="$GLOBAL_PREFIX/bin"

mkdir -p "$GLOBAL_BIN"

# 创建 ovogo shell 脚本
cat > "$GLOBAL_BIN/ovogo" << 'INNER_EOF'
#!/bin/bash
node "$PROJECT_DIR/dist/bin/ovogogogo.js" "$@"
INNER_EOF

# 替换实际路径
sed -i.bak "s|\$PROJECT_DIR|$PROJECT_DIR|g" "$GLOBAL_BIN/ovogo" 2>/dev/null || \
sed -i "s|\$PROJECT_DIR|$PROJECT_DIR|g" "$GLOBAL_BIN/ovogo" 2>/dev/null || true
rm -f "$GLOBAL_BIN/ovogo.bak" 2>/dev/null

chmod +x "$GLOBAL_BIN/ovogo"
echo -e "${GREEN}[OK]${NC} 全局命令 \"ovogo\" 已创建: $GLOBAL_BIN/ovogo"

# ── 7. 检查 PATH ────────────────────────────
if ! echo "$PATH" | tr ':' '\n' | grep -q "$GLOBAL_BIN"; then
    echo -e "${YELLOW}[WARN]${NC} $GLOBAL_BIN 不在 PATH 中"
    echo ""
    echo "请将以下行添加到 ~/.bashrc 或 ~/.zshrc:"
    echo "  export PATH=\"$GLOBAL_BIN:\$PATH\""
    echo ""
    echo "然后运行: source ~/.bashrc  (或 source ~/.zshrc)"
fi

# ── 8. 验证 ─────────────────────────────────
echo ""
echo "============================================="
echo "  安装验证"
echo "============================================="
echo ""

export PATH="$GLOBAL_BIN:$PATH"
if command -v ovogo &> /dev/null; then
    echo -n "运行: ovogo --version  →  "
    ovogo --version
    echo -e "${GREEN}[OK]${NC} ovogo 命令可用！"
else
    echo -e "${YELLOW}[WARN]${NC} ovogo 命令未立即生效，请手动刷新 PATH"
    echo "运行: export PATH=\"$GLOBAL_BIN:\$PATH\""
fi

echo ""
echo "============================================="
echo "  安装完成！"
echo "============================================="
echo ""
echo "使用方法:"
echo "  ovogo                          # 交互模式"
echo "  ovogo \"对目标进行渗透测试\"      # 直接任务"
echo "  ovogo --help                   # 查看帮助"
echo ""
echo "环境变量:"
echo "  export OPENAI_API_KEY=sk-xxx      # 设置 API 密钥"
echo "  export OVOGO_MODEL=gpt-4o         # 设置模型（可选）"
echo "  export OVOGO_MAX_ITER=200         # 设置最大轮数（可选）"
echo ""
