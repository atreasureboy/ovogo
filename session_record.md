# OVOGOGOGO — 会话档案 (Session Record)
> 创建时间: 2026-04-08
> 目的: 防止 Token 限制/中断导致项目崩塌，记录完整需求和进度

---

## 一、用户核心需求

### 项目定位
轻量级、OpenAI 调用方式的 mini 版 Claude Code。
不是 Anthropic SDK 版本，是 **OpenAI 兼容接口** 调用。

### 源码路径
`/project/cld-2.1.88/cdc-2.1.88/package/src-extracted/src/`

### 输出路径
`/project/ovogogogo/`

---

## 二、功能需求拆解

### 核心架构（脑 + 手）
1. **大脑 (Brain)** — Think-Act-Observe 决策循环
   - 参考: `QueryEngine.ts` + `query.ts`
   - 去掉 UI 依赖，保留 API 调用逻辑
   - 提取 coordinator/assistant System Prompt 精华

2. **手 (Hands)** — 工具执行层
   - `BashTool` — 执行 shell 命令，自主调试
   - `FileReadTool` — 读文件
   - `FileWriteTool` — 写文件
   - `FileEditTool` — 精确字符串替换
   - `GlobTool` — 文件模式搜索
   - `GrepTool` — 内容搜索

### 剥离内容（UI 层）
- 删除: React, Ink, `*.tsx` 相关
- 删除: `process.stdin` 的 TTY 交互
- 替换: 所有 UI 输出 → `process.stdout.write`

### API 调用方式
- **OpenAI 兼容接口** (不是 @anthropic-ai/sdk)
- 使用 `openai` npm 包
- 支持任何兼容 OpenAI 格式的端点 (OPENAI_BASE_URL)

---

## 三、断点续传协议

### 进度文件: `/project/ovogogogo/progress_log.json`
```json
{
  "current_step": "当前原子步骤名称",
  "extracted_files": ["已完成的文件列表"],
  "next_action": "下一步要做什么",
  "context_buffer": "关键上下文摘要"
}
```

---

## 四、目录结构

```
/project/ovogogogo/
├── session_record.md       # 本文件，会话档案
├── progress_log.json       # 断点续传状态
├── package.json
├── tsconfig.json
├── bin/
│   └── ovogogogo.ts        # 入口：CLI 驱动
└── src/
    ├── core/
    │   ├── engine.ts       # Think-Act-Observe 主循环
    │   ├── runner.ts       # 工具调用编排
    │   └── types.ts        # 核心类型
    ├── tools/
    │   ├── bash.ts         # BashTool — shell 执行
    │   ├── fileRead.ts     # 文件读取
    │   ├── fileWrite.ts    # 文件写入
    │   ├── fileEdit.ts     # 精确替换编辑
    │   ├── glob.ts         # 文件模式搜索
    │   ├── grep.ts         # 内容搜索
    │   └── index.ts        # 工具注册表
    └── prompts/
        ├── system.ts       # 主 System Prompt (从源码提取精华)
        └── tools.ts        # 工具描述 Prompt
```

---

## 五、执行序列（重构步骤）

| # | 步骤 | 状态 | 说明 |
|---|------|------|------|
| 0 | 创建会话档案 + 进度文件 | ✅ 完成 | 本文件 |
| 1 | 初始化阶段：目录结构 + 最小 TS 环境 | ✅ 完成 | package.json, tsconfig.json |
| 2 | 提取工具层：BashTool + 文件 IO | ✅ 完成 | src/tools/ |
| 3 | 移植决策循环：QueryEngine 核心 | ✅ 完成 | src/core/engine.ts |
| 4 | 注入灵魂：System Prompt 提取 | ✅ 完成 | src/prompts/ |
| 5 | 组装入口：bin/ovogogogo.ts | ✅ 完成 | bin/ovogogogo.ts |
| 6 | pnpm build + 联调测试 | ✅ 完成 | 构建成功，help 命令验证通过 |

---

## 六、关键源码参考点

| 文件 | 用途 |
|------|------|
| `src/QueryEngine.ts` | 主循环入口，协调 query/tools |
| `src/query.ts` | API 调用 + 工具执行闭环 |
| `src/tools/BashTool/BashTool.tsx` | shell 执行核心 |
| `src/tools/BashTool/prompt.ts` | BashTool System Prompt |
| `src/constants/prompts.ts` | 主 System Prompt 构建 |
| `src/coordinator/coordinatorMode.ts` | coordinator 模式逻辑 |
| `src/utils/queryContext.ts` | 上下文组装 |
| `src/tools/FileReadTool/` | 文件读取工具 |
| `src/tools/FileEditTool/` | 精确编辑工具 |

---

## 八、与官方版本的差距分析（Gap Analysis）

### 已实现
- Think-Act-Observe 核心循环
- OpenAI 兼容 API
- 6 个核心工具 (Bash/Read/Write/Edit/Glob/Grep)
- Claude Code 风格 TUI (✻ spinner, ⎿ tool display, ❯ prompt, ANSI colors)
- 交互式 REPL + 内置命令 (/clear /model /history /help /exit)
- System Prompt 工程（从源码提炼）
- 断点续传 progress log

### 差距清单（优先级排序）
见本文下方。

---

## 九、恢复指令

若进程中断，执行：
```bash
cat /project/ovogogogo/progress_log.json
# 查看 current_step 和 next_action，从该点继续
```
