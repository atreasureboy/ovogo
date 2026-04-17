#!/bin/bash
# ================================================================
#  Ovogo 一键环境配置脚本 (macOS / Linux)
#
#  功能：
#    1. 检测 Node.js + 包管理器 (pnpm / yarn / npm)
#    2. 安装依赖 (跳过已安装的情况)
#    3. 编译 TypeScript
#    4. 将 ovogogogo 添加为全局命令 ovogo
#    5. 验证安装
# ================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
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

# ── 2. 确定项目根目录 ────────────────────────
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

# ── 3. 选择包管理器 ─────────────────────────
# 优先级: pnpm > yarn > npm
# 如果 node_modules/.pnpm 存在，说明之前用 pnpm 安装过，必须继续用 pnpm
PKG_MANAGER=""
PKG_INSTALL_CMD=""

if [ -d "node_modules/.pnpm" ]; then
    # 之前用 pnpm 安装过
    if command -v pnpm &> /dev/null; then
        PKG_MANAGER="pnpm"
        PKG_INSTALL_CMD="pnpm install"
        PNPM_VER=$(pnpm -v)
        echo -e "${GREEN}[OK]${NC} pnpm 已安装: $PNPM_VER (检测到已有 pnpm 依赖)"
    else
        echo -e "${RED}[ERROR] 检测到项目使用 pnpm 管理依赖，但 pnpm 未安装${NC}"
        echo "安装 pnpm: npm install -g pnpm"
        echo "然后重新运行本脚本"
        exit 1
    fi
elif command -v pnpm &> /dev/null; then
    PKG_MANAGER="pnpm"
    PKG_INSTALL_CMD="pnpm install"
    PNPM_VER=$(pnpm -v)
    echo -e "${GREEN}[OK]${NC} pnpm 已安装: $PNPM_VER"
elif command -v yarn &> /dev/null; then
    PKG_MANAGER="yarn"
    PKG_INSTALL_CMD="yarn install"
    YARN_VER=$(yarn -v)
    echo -e "${GREEN}[OK]${NC} yarn 已安装: $YARN_VER"
elif command -v npm &> /dev/null; then
    PKG_MANAGER="npm"
    # --legacy-peer-deps 避免 peer dependency 冲突
    PKG_INSTALL_CMD="npm install --legacy-peer-deps"
    NPM_VER=$(npm -v)
    echo -e "${GREEN}[OK]${NC} npm 已安装: $NPM_VER"
else
    echo -e "${RED}[ERROR] 未找到任何包管理器 (pnpm / yarn / npm)${NC}"
    exit 1
fi

# ── 4. 安装依赖 ─────────────────────────────
echo ""
echo -e "${BLUE}[1/3]${NC} 安装依赖 (使用 $PKG_MANAGER)..."

if [ -d "node_modules" ]; then
    echo -e "${YELLOW}[SKIP]${NC} node_modules 已存在，跳过安装"
    echo -e "       如需重新安装，请先删除 node_modules: ${CYAN}rm -rf node_modules${NC}"
else
    eval "$PKG_INSTALL_CMD"
    echo -e "${GREEN}[OK]${NC} 依赖安装完成"
fi

# ── 5. 编译 TypeScript ──────────────────────
echo ""
echo -e "${BLUE}[2/3]${NC} 编译 TypeScript..."

if [ -d "dist/bin" ] && [ -f "dist/bin/ovogogogo.js" ]; then
    echo -e "${YELLOW}[SKIP]${NC} dist/ 已存在，跳过编译"
    echo -e "       如需重新编译，请先删除 dist: ${CYAN}rm -rf dist${NC}"
else
    eval "$PKG_MANAGER run build"
    echo -e "${GREEN}[OK]${NC} 编译完成"
fi

# ── 6. 添加全局命令 ovogo ──────────────────
echo ""
echo -e "${BLUE}[3/3]${NC} 添加全局命令 \"ovogo\"..."

BIN_FILE="$PROJECT_DIR/dist/bin/ovogogogo.js"
if [ ! -f "$BIN_FILE" ]; then
    echo -e "${RED}[ERROR] 编译输出未找到: $BIN_FILE${NC}"
    exit 1
fi

# 尝试使用已安装的包管理器获取全局路径，回退到默认值
if [ "$PKG_MANAGER" = "pnpm" ]; then
    GLOBAL_PREFIX=$(pnpm root -g 2>/dev/null | xargs dirname 2>/dev/null || npm prefix -g 2>/dev/null || echo "$HOME/.local")
elif [ "$PKG_MANAGER" = "yarn" ]; then
    GLOBAL_PREFIX=$(yarn global bin 2>/dev/null || npm prefix -g 2>/dev/null || echo "$HOME/.local")
else
    GLOBAL_PREFIX=$(npm prefix -g 2>/dev/null || echo "$HOME/.local")
fi
GLOBAL_BIN="$GLOBAL_PREFIX/bin"

mkdir -p "$GLOBAL_BIN"

# 检查是否已存在
if [ -f "$GLOBAL_BIN/ovogo" ]; then
    echo -e "${YELLOW}[SKIP]${NC} $GLOBAL_BIN/ovogo 已存在，跳过创建"
else
    # 创建 ovogo shell 脚本 (使用绝对路径，避免子 shell 变量丢失)
    printf '#!/bin/bash\nnode "%s/dist/bin/ovogogogo.js" "$@"\n' "$PROJECT_DIR" > "$GLOBAL_BIN/ovogo"
    chmod +x "$GLOBAL_BIN/ovogo"
    echo -e "${GREEN}[OK]${NC} 全局命令 \"ovogo\" 已创建: $GLOBAL_BIN/ovogo"
fi

# ── 7. 检查 PATH ────────────────────────────
if ! echo "$PATH" | tr ':' '\n' | grep -q "$GLOBAL_BIN"; then
    echo -e "${YELLOW}[WARN]${NC} $GLOBAL_BIN 不在 PATH 中"
    echo ""
    echo "请将以下行添加到 ~/.bashrc 或 ~/.zshrc:"
    echo "  ${CYAN}export PATH=\"$GLOBAL_BIN:\$PATH\"${NC}"
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
    echo "运行: ${CYAN}export PATH=\"$GLOBAL_BIN:\$PATH\"${NC}"
fi

echo ""
echo "============================================="
echo "  安装完成！"
echo "============================================="
echo ""
echo "使用方法:"
echo "  ${CYAN}ovogo${NC}                          # 交互模式"
echo "  ${CYAN}ovogo \"对目标进行渗透测试\"${NC}      # 直接任务"
echo "  ${CYAN}ovogo --help${NC}                   # 查看帮助"
echo ""
echo "环境变量:"
echo "  ${CYAN}export OPENAI_API_KEY=sk-xxx${NC}      # 设置 API 密钥"
echo "  ${CYAN}export OPENAI_BASE_URL=https://...${NC} # 兼容端点 (可选)"
echo "  ${CYAN}export OVOGO_MODEL=gpt-4o${NC}         # 设置模型 (可选)"
echo "  ${CYAN}export OVOGO_MAX_ITER=200${NC}         # 设置最大轮数 (可选)"
echo ""
