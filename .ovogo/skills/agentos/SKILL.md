---
name: agentos
description: AgentOS 架构设计参考。当用户开发 Agent、设计 Agent 系统、讨论 Harness/Binding/Run/Skill/Memory/Channel/Scheduler/通信原语等 AgentOS 概念时使用。包含完整架构规范，可通过 /agentos 直接调用。
version: 1.0.0
---

# AgentOS 架构参考

> **SSOT**：完整规范在 `/agent/agentOS.md`（v4，2026-03-27）。本 Skill 是结构化速查层，读取该文件获取完整细节。

当用户问到具体章节细节时，执行：`Read /agent/agentOS.md`

---

## 核心定位

**AgentOS = Agent Harness**
- 模型是 CPU，上下文窗口是 RAM，AgentOS 是操作系统
- 负责：boot sequence、内存管理、技能调度、生命周期钩子、安全隔离
- 参考系：Agno（执行层）、Claude Code（Harness 工程）、MemGPT（分层内存）、K8s（控制器模式）

---

## 一、整体分层（从上到下）

```
Channel Layer        → 统一消息入口（Webhook / 飞书 / 微信）
API Gateway Layer    → FastAPI + uvicorn + JWT/RBAC + SSE
Security Layer       → 六层纵深防御
Binding & Run Layer  → 外部会话管理 + 执行入口
Harness Layer        → 统一 Agent 运行时（Boot/Hooks/Context/Trajectory/Comm/Reflection）
Entity Layer         → Agent + Skill
Module Layer         → Memory / Scheduler / Workspace / Reflection
Async Task Engine    → runs 队列（Postgres SKIP LOCKED）+ Worker + Scheduler 进程
Remote Node Layer    → mTLS WebSocket 连接
Storage Layer        → Postgres + pgvector
```

---

## 二、实体模型

### Agent（统一模型，无 persistent/stateless 二分）

| 字段 | 说明 | 默认 |
|------|------|------|
| `identity` | SOUL（角色/行为边界/价值观） | 可选 |
| `modules` | 启用的能力模块列表 | `[]` |
| `tools` | 授权 Tool 白名单 | 必填 |
| `skill_ids` | 关联 Skill ID 列表 | `[]` |
| `role` | 角色标签（用于角色寻址） | 可选 |
| `tags` | 分组标签（组建团队/筛选） | `[]` |
| `access_policy` | 访问策略（invoke/dispatch/message） | null（同 Tenant 开放） |
| `model` | LLM 模型 | 必填 |

**模块组合示例**：
- 翻译助手：`[]` → 纯无状态
- 有记忆客服：`[memory]`
- 7x24 运维员：`[memory, scheduler, workspace, reflection]`
- 代码审查员：`[memory, workspace]`

**Team = 共享 tag 的 Agent 集合**（不是独立实体，无 Team/Workflow 表）

### Skill

`Skill = Prompt 模板 + Tool 集合 + Hooks + 输入/输出 Schema`

- 独立注册，一个 Skill 可被多个 Agent 使用
- Boot 时只注入 Skill 索引（名称+描述），完整 prompt 通过 `load_skill` tool 懒加载
- `manifest.tools` 必须是 Agent `tools` 的子集

---

## 三、Agent 模块系统

| 模块 | 标识 | 能力 | 依赖 |
|------|------|------|------|
| Memory | `memory` | Semantic+Episodic 记忆、Boot 检索、Memory Tool | Embedding Service |
| Scheduler | `scheduler` | Cron 定时任务、Heartbeat 巡检 | Scheduler 进程 |
| Workspace | `workspace` | 持久化文件目录（per-agent 隔离） | 本地/远程 FS |
| Reflection | `reflection` | Run 后自我反思、经验提取写入 Memory | Memory 模块 |

### Boot Sequence（所有 Agent 统一）

```
Step 1: Load Identity（SOUL → system prompt，否则 base prompt）
Step 2: Load Base Prompt + Tools + 通信 Tools
Step 3: Retrieve Memory [仅 memory 模块]（embed → 检索 Semantic+Episodic → 合并排序）
Step 4: Load Skill Index（若有 skill_ids → 注入索引）
Step 5: Inject Team Context + Pending Messages（同 tag 队友列表 + agent_messages 收件箱）
Step 6: Context Budget Allocation [仅 memory 模块]（按比例分配 token）
Step 7: Assemble & Dispatch → agno Agent 执行 + Trajectory 记录
```

---

## 四、Binding 与 Run

### Binding（外部会话上下文）

- 仅用于用户发起的交互会话（Channel 消息路由到 Binding）
- 系统任务（Cron/Heartbeat/Agent 调用）直接创建 Run，不需要 Binding
- 同一 Binding 内 runs 强制串行（Advisory Lock `binding_id_hash`）

### Run（执行最小单元）

| trigger | 来源 | 需要 Binding |
|---------|------|:---:|
| `user` | POST /bindings/{id}/runs | 是 |
| `channel` | Channel Router | 是 |
| `heartbeat` | Scheduler | 否 |
| `cron` | Scheduler | 否 |
| `agent_invoke` | invoke_agent tool | 否（child run） |

**Run 状态机**：`pending → running → completed / failed`（终态不可变）

---

## 五、Harness Layer

### Lifecycle Hooks

| Hook | 触发时机 | 典型用途 |
|------|---------|---------|
| PreToolUse | Tool 调用前 | 权限检查、参数审计 |
| PostToolUse | Tool 调用后 | 结果记录、输出过滤 |
| OnError | 执行异常时 | 回退策略、告警 |
| OnComplete | Run 正常结束 | 触发 Reflection、通知 Channel |
| OnContextOverflow | 上下文接近限制 | 自动压缩、摘要保留 |

Hook 优先级（低→高）：Skill 级 → Agent 级 → 全局 Security Policy

### Context Budget（仅 memory 模块启用时）

```
总窗口（如 128K）
├── Identity/SOUL (~2K，固定)
├── Memory Budget (上限 30%，动态)
│   ├── Semantic top-K (~5K)
│   └── Episodic recent (~3K)
├── Skill Index (~1K，固定)
├── System Overhead (~2K)
└── Task Available（剩余）
```

溢出策略：按相关性分数降序截断，被截断记忆记录到 Trajectory

---

## 六、Agent Communication Layer

### 三个通信原语

| 原语 | 语义 | 返回 | 调用方 |
|------|------|------|--------|
| `invoke_agent(target, task)` | 同步委托，等待结果 | result | 阻塞 |
| `dispatch_agent(target, task)` | 异步派发，不等待 | run_id | 继续执行 |
| `send_message(target, message)` | 异步通知，写收件箱 | message_id | 立即返回 |

**target 寻址方式**：
- `agent_id`（直接，高耦合）
- `role`（角色寻址，推荐）
- `{role, tag}`（限定角色，最灵活）

**target 可为数组**：invoke/dispatch 支持并行多目标

### 间接通信：Workspace（蚂蚁信息素模型）

```
CEO 写 workspace://tasks/001.md
→ Dev（cron 巡检）发现 → 执行 → 写 workspace://outputs/001.md
→ QA（cron 巡检）发现 → 审查 → 写 workspace://reviews/001.md
```

无需直接通信，通过共享环境自然协调。

### Agent 间通信 vs Sub-agent

| | 注册 Agent（invoke/dispatch） | Sub-agent（agno 原生） |
|--|------------------------------|----------------------|
| 身份 | 有 SOUL | 无（匿名） |
| 记忆 | 有 Memory | 无 |
| 上下文 | **隔离** | 继承父 Agent |
| 生命周期 | 持久化 | 用完即弃 |
| 适用 | 需要专业视角/经验/身份 | 并行加速同质化子任务 |

**决策树**：需要对方专业视角/经验 → invoke/dispatch 注册 Agent。只是活太多需要并行 → sub-agent。

### 安全边界

- **Tenant 隔离**（硬边界）：跨 Tenant 完全不可见，RLS 自动执行
- **access_policy**（可选）：被调用方声明允许 invoke/dispatch/message 的调用方列表
- **速率限制**：per-Agent 出站 invoke 10/min，dispatch 50/min，message 100/min
- **调用链循环检测**：`call_chain` 传播，已在链中 → 拒绝，链长 ≥ 10 → 拒绝

### Event Log（不可变事件流）

所有通信原语自动写入 `agent_event_log`，Agent 无需手动维护任务状态。

事件类型：`INVOKE_SENT / DISPATCH_SENT / MESSAGE_SENT / ACCEPTED / COMPLETED / FAILED / TIMEOUT / CALLBACK_TRIGGERED / VERIFIED / REJECTED`

### 验证闸门（dispatch + acceptance_criteria）

```
dispatch(CEO→Dev, task + criteria)
→ Dev 完成 → 携带 evidence 回调
→ Harness 自动 invoke QA 独立验证
→ VERIFIED → Event Log 记录
→ REJECTED → 自动 dispatch Dev 重做
```

**原则**：No Tuple, No Merge（无证据的"完成"不算完成）

### 审计 Agent 模式

专职 Auditor Agent + scheduler 模块，定期扫描 Event Log，发现未闭环任务，生成问责报告，send_message 催促。

Task View = 从 Event Log 投影的只读视图（不是独立实体）。

---

## 七、Memory Module

**两层架构**：
- **Semantic Memory**：去语境化抽象知识、用户偏好、业务规则（pgvector 检索）
- **Episodic Memory**：带时间戳的具体经历（按 event_date 分区，可整合提升为 Semantic）

**Memory Tool**（执行中可用）：
- `memory_write(content, source)` → 记录知识
- `memory_search(query, top_k)` → 补充检索
- `memory_recall(time_range)` → 回忆经历
- `memory_flag_conflict(memory_id, reason)` → 标记冲突

**来源置信度**：`user_stated > agent_inferred > tool_observed`

**Memory 写入并发控制**：Advisory Lock `agent_id_hash`（独立于 Binding Lane 锁）

---

## 八、Skill System

```json
{
  "id": "skill_pr_review",
  "name": "PR 代码审查",
  "description": "...",
  "version": "1.2.0",
  "manifest": {
    "tools": ["git_diff", "code_search", "comment_create"],
    "input_schema": {},
    "output_schema": {}
  },
  "prompt": "...",
  "hooks": [],
  "status": "active"
}
```

生命周期：`draft → active → deprecated`

---

## 九、API 路由概览

```
实体注册:    POST/GET/PUT/DELETE /agents  /skills
Binding:    POST /agents/{id}/bindings
            PATCH/GET/DELETE /bindings/{id}
执行:       POST /bindings/{id}/runs  → task_id
            GET  /runs/{task_id}/events?last_event_id={id}  (SSE)
Channel:    POST /channels  /channels/webhook/{id}
Cron:       POST/GET/PATCH/DELETE /cron-jobs  /cron-jobs/{id}/trigger
Memory:     GET/POST/DELETE /agents/{id}/memories
```

SSE 支持断点续传（`last_event_id` 参数）。

---

## 十、安全（六层纵深）

1. **身份认证**：JWT RS256 + RBAC + API Scope
2. **数据加密**：TLS 1.3 + AES-256-GCM 字段级 + 数据脱敏
3. **沙箱隔离**：Worker 进程隔离 + chroot + 网络白名单 + cgroup
4. **Agent 边界**：Tool 白名单 + 输出审查 + 提示词注入防御
5. **多租户隔离**：RLS（Row Level Security）
6. **全链路审计**：操作日志全留痕 + 实时异常检测

---

## 完整规范

详细内容（含完整 mermaid 图、Schema、示例）见：`/agent/agentOS.md`

章节索引：
- 一、整体分层架构
- 二、实体模型（Agent / Skill / Sub-agent / 多 Agent 协作）
- 三、Agent 模块系统（Boot Sequence 详解）
- 四、Binding 与 Run（内存并发模型）
- 五、Harness Layer（Hooks / Context Budget / Trajectory / Reflection Loop）
- 六、Agent Communication Layer（通信原语 / Workspace / Event Log / 验证闸门 / 审计 Agent）
- 七、Skill System（Loader 机制 / 安全约束）
- 八、Memory Module（读写路径 / 冲突检测 / 整合 Cron）
- 九、Channel Layer（Webhook Adapter / Permission Relay）
- 十、Scheduler Module（Cron Job / Heartbeat / 容错）
- 十一、API 路由设计
- 十二、Async Task Engine 数据流（容错 / 事件推送可靠性）
- 十三、Remote Node 连接模型
- 十四、Security Layer
