@echo off
REM ================================================================
REM  Ovogo 一键环境配置脚本 (Windows)
REM
REM  功能：
REM    1. 检测 Node.js + 包管理器 (pnpm / yarn / npm)
REM    2. 安装依赖 (跳过已安装的情况)
REM    3. 编译 TypeScript
REM    4. 将 ovogogogo 添加为全局命令 ovogo
REM    5. 验证安装
REM ================================================================

echo.
echo =============================================
echo   Ovogo 环境配置 — Windows
echo =============================================
echo.

REM ── 1. 检查 Node.js ──────────────────────────
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Node.js 未安装！
    echo 请先从 https://nodejs.org 下载安装 Node.js ^(建议 LTS 版本^)
    echo 安装后重新运行本脚本
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('node -v') do set NODE_VER=%%i
echo [OK] Node.js 已安装: %NODE_VER%

REM ── 2. 确定项目根目录 ────────────────────────
set "PROJECT_DIR=%~dp0"
set "PROJECT_DIR=%PROJECT_DIR:~0,-1%"
cd /d "%PROJECT_DIR%"

REM ── 3. 选择包管理器 ─────────────────────────
REM 优先级: pnpm > yarn > npm
REM 如果 node_modules\.pnpm 存在，说明之前用 pnpm 安装过
set PKG_MANAGER=
set PKG_INSTALL_CMD=

if exist "node_modules\.pnpm" (
    where pnpm >nul 2>nul
    if %errorlevel% equ 0 (
        set PKG_MANAGER=pnpm
        set PKG_INSTALL_CMD=pnpm install
        for /f "tokens=*" %%i in ('pnpm -v') do set PM_VER=%%i
        echo [OK] pnpm 已安装: %PM_VER% ^(检测到已有 pnpm 依赖^)
    ) else (
        echo [ERROR] 检测到项目使用 pnpm 管理依赖，但 pnpm 未安装
        echo 安装 pnpm: npm install -g pnpm
        echo 然后重新运行本脚本
        pause
        exit /b 1
    )
) else (
    where pnpm >nul 2>nul
    if %errorlevel% equ 0 (
        set PKG_MANAGER=pnpm
        set PKG_INSTALL_CMD=pnpm install
        for /f "tokens=*" %%i in ('pnpm -v') do set PM_VER=%%i
        echo [OK] pnpm 已安装: %PM_VER%
    ) else (
        where yarn >nul 2>nul
        if %errorlevel% equ 0 (
            set PKG_MANAGER=yarn
            set PKG_INSTALL_CMD=yarn install
            for /f "tokens=*" %%i in ('yarn -v') do set PM_VER=%%i
            echo [OK] yarn 已安装: %PM_VER%
        ) else (
            where npm >nul 2>nul
            if %errorlevel% equ 0 (
                set PKG_MANAGER=npm
                REM --legacy-peer-deps 避免 peer dependency 冲突
                set PKG_INSTALL_CMD=npm install --legacy-peer-deps
                for /f "tokens=*" %%i in ('npm -v') do set PM_VER=%%i
                echo [OK] npm 已安装: %PM_VER%
            ) else (
                echo [ERROR] 未找到任何包管理器 (pnpm / yarn / npm)
                pause
                exit /b 1
            )
        )
    )
)

REM ── 4. 安装依赖 ─────────────────────────────
echo.
echo [1/3] 安装依赖 (使用 %PKG_MANAGER%)...

if exist "node_modules" (
    echo [SKIP] node_modules 已存在，跳过安装
    echo        如需重新安装，请先删除 node_modules
) else (
    call %PKG_INSTALL_CMD%
    if %errorlevel% neq 0 (
        echo [ERROR] 依赖安装失败
        pause
        exit /b 1
    )
    echo [OK] 依赖安装完成
)

REM ── 5. 编译 TypeScript ──────────────────────
echo.
echo [2/3] 编译 TypeScript...

if exist "dist\bin\ovogogogo.js" (
    echo [SKIP] dist/ 已存在，跳过编译
    echo        如需重新编译，请先删除 dist
) else (
    call %PKG_MANAGER% run build
    if %errorlevel% neq 0 (
        echo [ERROR] 编译失败
        pause
        exit /b 1
    )
    echo [OK] 编译完成
)

REM ── 6. 添加全局命令 ovogo ──────────────────
echo.
echo [3/3] 添加全局命令 "ovogo"...

set "BIN_FILE=%PROJECT_DIR%\dist\bin\ovogogogo.js"
if not exist "%BIN_FILE%" (
    echo [ERROR] 编译输出未找到: %BIN_FILE%
    pause
    exit /b 1
)

REM 获取全局 bin 目录
for /f "tokens=*" %%i in ('npm prefix -g') do set "GLOBAL_PREFIX=%%i"
set "GLOBAL_BIN=%GLOBAL_PREFIX%\bin"

REM 确保全局 bin 目录存在
if not exist "%GLOBAL_BIN%" mkdir "%GLOBAL_BIN%"

REM 检查是否已存在
if exist "%GLOBAL_BIN%\ovogo.cmd" (
    echo [SKIP] %GLOBAL_BIN%\ovogo.cmd 已存在，跳过创建
) else (
    REM 创建 ovogo.cmd（Windows 全局命令）
    (
    echo @echo off
    echo node "%BIN_FILE%" %%*
    ) > "%GLOBAL_BIN%\ovogo.cmd"
    echo [OK] 全局命令 "ovogo" 已创建: %GLOBAL_BIN%\ovogo.cmd
)

REM ── 7. 验证 ─────────────────────────────────
echo.
echo =============================================
echo   安装验证
echo =============================================
echo.

REM 刷新 PATH
set "PATH=%GLOBAL_BIN%;%PATH%"

echo 运行: ovogo --version
call ovogo --version 2>nul
if %errorlevel% neq 0 (
    echo [WARN] ovogo 命令未生效，可手动添加以下路径到系统环境变量 PATH:
    echo   %GLOBAL_BIN%
    echo 或者使用完整路径运行: node "%BIN_FILE%"
) else (
    echo [OK] ovogo 命令可用！
)

echo.
echo =============================================
echo   安装完成！
echo =============================================
echo.
echo 使用方法:
echo   ovogo                          # 交互模式
echo   ovogo "对目标进行渗透测试"      # 直接任务
echo   ovogo --help                   # 查看帮助
echo.
echo 环境变量:
echo   set OPENAI_API_KEY=sk-xxx      # 设置 API 密钥
echo   set OPENAI_BASE_URL=https://   # 兼容端点 (可选)
echo   set OVOGO_MODEL=gpt-4o         # 设置模型 (可选)
echo   set OVOGO_MAX_ITER=200         # 设置最大轮数 (可选)
echo.
pause
