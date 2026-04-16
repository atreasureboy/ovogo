# LangGraph 架构改造总结

## 改造完成

已成功将 ovogogogo 项目从原有的 ExecutionEngine 架构改造为 LangGraph 状态图架构。

## 新增文件

### 核心文件
1. **src/core/graph/types.ts** - 状态类型定义
   - GraphState（共享状态）
   - Finding, Port, WebService, Credential, Shell（数据结构）
   - AgentExecutionResult（agent 执行结果）

2. **src/core/graph/nodes/supervisor.ts** - Supervisor 节点
   - 主协调节点，负责决策和路由
   - 调用 LLM 分析当前状态
   - 返回下一步行动（delegate_xxx, finish, wait）

3. **src/core/graph/nodes/workers.ts** - Worker 节点
   - 子 agent 工作节点
   - 在 tmux 中执行具体任务
   - 从共享状态提取上下文，更新共享状态

4. **src/core/graph/builder.ts** - 图构建器
   - 构建完整的状态图
   - 定义节点和边
   - 条件路由逻辑

5. **src/core/langGraphEngine.ts** - LangGraph 引擎
   - 替代原有的 ExecutionEngine
   - 流式执行状态图
   - 渲染状态更新和最终总结

6. **bin/agent-worker.ts** - Agent Worker 独立进程
   - 在 tmux 中运行的独立进程
   - 从 context 文件读取输入
   - 写结果到 done 文件

7. **src/core/langGraphIntegration.ts** - 集成辅助函数
   - shouldUseLangGraph() - 检测是否启用 LangGraph
   - runWithLangGraph() - 执行 LangGraph 任务

### 文档
8. **docs/LANGGRAPH_GUIDE.md** - 使用指南
   - 启用方式
   - 架构对比
   - 工作流程
   - 状态结构
   - 调试方法

## 依赖更新

在 package.json 中添加：
```json
"@langchain/core": "^0.3.0",
"@langchain/langgraph": "^0.2.0"
```

## 架构对比

### 原架构
```
主 agent (ExecutionEngine)
  ├─ Agent 工具调用 → 子 agent (独立 engine)
  ├─ MultiAgent 工具 → 多个子 agent (Promise.all)
  └─ 子 agent 返回文本结果 → 主 agent 解析
```

**问题：**
- 子 agent 没有共享状态
- 主 agent 需要手动解析和传递信息
- 决策逻辑分散在主 agent 的 prompt 中

### 新架构（LangGraph）
```
StateGraph
  ├─ Supervisor 节点（决策）
  │   └─ LLM 分析状态 → 路由决策
  ├─ Worker 节点（执行）
  │   ├─ recon (tmux)
  │   ├─ vuln-scan (tmux)
  │   ├─ exploit (tmux)
  │   └─ ...
  └─ 共享状态（自动合并）
      ├─ findings
      ├─ openPorts
      ├─ shells
      └─ credentials
```

**优势：**
- 清晰的状态管理
- 灵活的流程控制
- 保留 tmux 执行
- 易于调试和扩展

## 使用方式

### 启用 LangGraph 模式

**方式 1: 环境变量**
```bash
export OVOGO_LANGGRAPH=true
node dist/bin/ovogogogo.js "对 example.com 进行渗透测试"
```

**方式 2: 命令行参数**
```bash
node dist/bin/ovogogogo.js --langgraph "对 example.com 进行渗透测试"
```

**方式 3: 配置文件**
在 `.ovogo/settings.json` 中添加：
```json
{
  "useLangGraph": true
}
```

### 编译和运行

```bash
# 安装新依赖
pnpm install

# 编译
npm run build

# 运行（LangGraph 模式）
node dist/bin/ovogogogo.js --langgraph "对 example.com 进行渗透测试"
```

## 工作流程

1. **初始化** → 创建共享状态
2. **Supervisor** → 分析状态，决定启动 recon
3. **recon Worker** → 在 tmux 中执行侦察
4. **recon 完成** → 更新状态（subdomains, ips, openPorts）
5. **Supervisor** → 分析新状态，决定启动 vuln-scan
6. **vuln-scan Worker** → 在 tmux 中执行漏洞扫描
7. **vuln-scan 完成** → 更新状态（findings）
8. **Supervisor** → 发现 critical 漏洞，决定启动 exploit
9. **exploit Worker** → 在 tmux 中执行漏洞利用
10. **exploit 完成** → 更新状态（shells）
11. **循环** → 直到任务完成

## 状态共享示例

```typescript
// Worker 节点从共享状态提取上下文
const context = {
  task: "对 example.com 进行渗透测试",
  primaryTarget: "example.com",
  sessionDir: "/path/to/sessions/...",
  openPorts: [80, 443, 8080],  // 来自 recon 阶段
  webServices: ["http://example.com", ...],  // 来自 recon 阶段
  findings: [  // 来自 vuln-scan 阶段
    { severity: "critical", title: "SQL Injection", ... }
  ]
}

// Worker 执行完成后更新状态
return {
  shells: [
    { id: "shell_4444", type: "reverse", status: "active" }
  ],
  findings: [
    { severity: "critical", title: "SQL Injection RCE", ... }
  ]
}
```

## 下一步集成

需要在 `bin/ovogogogo.ts` 的 `main()` 函数中添加：

```typescript
import { shouldUseLangGraph, runWithLangGraph } from '../src/core/langGraphIntegration.js'

// 在创建 engine 之前
const useLangGraph = shouldUseLangGraph(process.argv, settings)

if (useLangGraph) {
  if (task) {
    await runWithLangGraph({
      task,
      model,
      apiKey,
      baseURL: process.env.OPENAI_BASE_URL,
      sessionDir,
      primaryTarget,
      cwd,
      renderer,
    })
    return
  }
  
  renderer.warn('LangGraph 模式暂不支持 REPL')
  process.exit(1)
}

// 原有的 ExecutionEngine 逻辑
const engine = new ExecutionEngine(config, renderer)
```

## 注意事项

1. **Ubuntu 环境** - 需要在 Ubuntu 上运行（依赖 tmux）
2. **编译** - 修改代码后需要 `npm run build`
3. **单次任务** - 目前只支持单次任务模式，不支持 REPL
4. **依赖安装** - 需要先 `pnpm install` 安装 LangGraph 依赖

## 调试

查看 agent 日志：
```bash
ls sessions/example.com_*/
# recon_log.txt, recon_context.json, recon_done.json
```

查看 tmux 会话：
```bash
tmux list-sessions
tmux attach -t ovogo-recon-1234567890
```

## 完成状态

✅ 状态类型定义
✅ Supervisor 节点
✅ Worker 节点
✅ 图构建器
✅ LangGraph 引擎
✅ Agent Worker 独立进程
✅ 集成辅助函数
✅ 使用文档
✅ package.json 依赖更新

**待完成：** 在 bin/ovogogogo.ts 中集成（需要你手动添加几行代码）
