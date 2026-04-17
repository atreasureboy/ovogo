@echo off
REM ================================================================
REM  Ovogo 一键环境配置脚本 (Windows)
REM
REM  功能：
REM    1. 检测并安装 Node.js
REM    2. 安装 npm 依赖
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
    echo 请先从 https://nodejs.org 下载安装 Node.js (建议 LTS 版本)
    echo 安装后重新运行本脚本
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('node -v') do set NODE_VER=%%i
echo [OK] Node.js 已安装: %NODE_VER%

REM ── 2. 检查 npm ─────────────────────────────
where npm >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] npm 未找到！请重新安装 Node.js
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('npm -v') do set NPM_VER=%%i
echo [OK] npm 已安装: %NPM_VER%

REM ── 3. 安装依赖 ─────────────────────────────
echo.
echo [1/3] 安装 npm 依赖...
call npm install
if %errorlevel% neq 0 (
    echo [ERROR] npm install 失败
    pause
    exit /b 1
)
echo [OK] 依赖安装完成

REM ── 4. 编译 TypeScript ──────────────────────
echo.
echo [2/3] 编译 TypeScript...
call npm run build
if %errorlevel% neq 0 (
    echo [ERROR] 编译失败
    pause
    exit /b 1
)
echo [OK] 编译完成

REM ── 5. 添加全局命令 ovogo ──────────────────
echo.
echo [3/3] 添加全局命令 "ovogo"...

REM 获取脚本所在目录（项目根目录）的绝对路径
set "PROJECT_DIR=%~dp0"
REM 去掉末尾反斜杠
set "PROJECT_DIR=%PROJECT_DIR:~0,-1%"

set "BIN_DIR=%PROJECT_DIR%\dist\bin"
set "BIN_FILE=%BIN_DIR%\ovogogogo.js"

if not exist "%BIN_FILE%" (
    echo [ERROR] 编译输出未找到: %BIN_FILE%
    echo 请先运行 npm run build
    pause
    exit /b 1
)

REM 创建包装脚本到 npm 全局 bin 目录
for /f "tokens=*" %%i in ('npm prefix -g') do set "GLOBAL_PREFIX=%%i"
set "GLOBAL_BIN=%GLOBAL_PREFIX%\bin"
set "GLOBAL_NODE=%GLOBAL_PREFIX%\node_modules"

REM 确保全局 bin 目录存在
if not exist "%GLOBAL_BIN%" mkdir "%GLOBAL_BIN%"

REM 创建 ovogo.cmd（Windows 全局命令）
(
echo @echo off
echo node "%BIN_FILE%" %%*
) > "%GLOBAL_BIN%\ovogo.cmd"

echo [OK] 全局命令 "ovogo" 已创建: %GLOBAL_BIN%\ovogo.cmd

REM ── 6. 验证 ─────────────────────────────────
echo.
echo =============================================
echo   安装验证
echo =============================================
echo.

REM 刷新 PATH（让新创建的 cmd 立即可用）
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
echo   set OVOGO_MODEL=gpt-4o         # 设置模型（可选）
echo   set OVOGO_MAX_ITER=200         # 设置最大轮数（可选）
echo.
pause
