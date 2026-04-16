/**
 * LangGraph 模式使用指南
 *
 * ## 启用方式
 *
 * ### 方式 1: 环境变量
 * ```bash
 * export OVOGO_LANGGRAPH=true
 * node dist/bin/ovogogogo.js "对 example.com 进行渗透测试"
 * ```
 *
 * ### 方式 2: 命令行参数
 * ```bash
 * node dist/bin/ovogogogo.js --langgraph "对 example.com 进行渗透测试"
 * ```
 *
 * ### 方式 3: 配置文件
 * 在 `.ovogo/settings.json` 中添加：
 * ```json
 * {
 *   "useLangGraph": true,
 *   "engagement": {
 *     "targets": ["example.com"]
 *   }
 * }
 * ```
 *
 * ## 架构对比
 *
 * ### 原架构（ExecutionEngine）
 * - 主 agent 通过 Agent/MultiAgent 工具调用子 agent
 * - 每个子 agent 是独立的 engine 实例
 * - 子 agent 没有共享状态，只能通过返回值传递信息
 * - 主 agent 需要手动解析子 agent 输出并决策
 *
 * ### 新架构（LangGraph）
 * - 使用状态图（StateGraph）管理整体流程
 * - Supervisor 节点负责决策和路由
 * - Worker 节点（子 agent）在 tmux 中执行
 * - 所有节点共享状态（findings, ports, shells, credentials）
 * - 自动状态合并和传递
 *
 * ## 工作流程
 *
 * 1. **初始化**
 *    - 创建 session 目录
 *    - 初始化共享状态
 *    - 启动状态图
 *
 * 2. **Supervisor 决策**
 *    - 分析当前状态（已完成阶段、发现的漏洞、活跃 agent）
 *    - 调用 LLM 决定下一步行动
 *    - 返回路由决策（delegate_recon, delegate_exploit, finish 等）
 *
 * 3. **Worker 执行**
 *    - 从共享状态提取上下文
 *    - 在 tmux 中启动 agent-worker.js
 *    - agent-worker 读取 context 文件，执行任务
 *    - 完成后写入 done 文件
 *    - Worker 节点读取结果，更新共享状态
 *
 * 4. **循环**
 *    - Worker 完成后回到 Supervisor
 *    - Supervisor 根据新状态决定下一步
 *    - 直到任务完成（finish）或出错（error）
 *
 * ## 状态结构
 *
 * ```typescript
 * {
 *   task: "对 example.com 进行渗透测试",
 *   primaryTarget: "example.com",
 *   sessionDir: "/path/to/sessions/example.com_20260415_120000",
 *   currentPhase: "exploit",
 *   completedPhases: Set(["recon", "vuln-scan"]),
 *   findings: [
 *     { severity: "critical", title: "SQL Injection", ... },
 *     { severity: "high", title: "XSS", ... }
 *   ],
 *   openPorts: [
 *     { port: 80, protocol: "tcp", service: "http" },
 *     { port: 443, protocol: "tcp", service: "https" }
 *   ],
 *   shells: [
 *     { id: "shell_4444", type: "reverse", status: "active" }
 *   ],
 *   messages: [
 *     { role: "supervisor", content: "[决策] delegate_exploit", ... },
 *     { role: "worker", content: "漏洞利用完成，获得 shell", agentType: "manual-exploit", ... }
 *   ],
 *   nextAction: "delegate_post_exploit",
 *   activeAgents: Set(["manual-exploit"])
 * }
 * ```
 *
 * ## 子 agent 通信
 *
 * ### 输入（context 文件）
 * ```json
 * {
 *   "task": "对 example.com 进行渗透测试",
 *   "primaryTarget": "example.com",
 *   "sessionDir": "/path/to/sessions/...",
 *   "currentPhase": "exploit",
 *   "findings": [...],
 *   "openPorts": [...],
 *   "webServices": [...]
 * }
 * ```
 *
 * ### 输出（done 文件）
 * ```json
 * {
 *   "agentType": "manual-exploit",
 *   "success": true,
 *   "summary": "成功利用 SQL 注入漏洞，获得 webshell",
 *   "outputFiles": ["exploit_log.txt", "webshell.php"],
 *   "findings": [
 *     { "severity": "critical", "title": "SQL Injection RCE", ... }
 *   ],
 *   "shells": [
 *     { "id": "shell_4444", "type": "reverse", "status": "active" }
 *   ],
 *   "duration": 45000
 * }
 * ```
 *
 * ## 优势
 *
 * 1. **清晰的状态管理** - 所有信息在共享状态中，不会丢失
 * 2. **灵活的流程控制** - Supervisor 可以根据结果动态调整
 * 3. **保留 tmux 执行** - 子 agent 依然在 tmux 中运行，便于监控
 * 4. **支持并行** - 可以同时启动多个 worker（未来扩展）
 * 5. **易于调试** - 状态变化可追踪，每个节点输入输出明确
 * 6. **支持人工介入** - 可以在 Supervisor 节点暂停等待用户输入
 *
 * ## 限制
 *
 * 1. **暂不支持 REPL** - 目前只支持单次任务模式
 * 2. **需要编译** - 修改代码后需要 `npm run build`
 * 3. **依赖 tmux** - 必须在 Linux/macOS 环境运行
 *
 * ## 调试
 *
 * ### 查看状态变化
 * 状态图执行时会输出每个节点的状态更新：
 * ```
 * [supervisor] [决策] delegate_recon
 * 推理: 开局阶段，启动侦察
 *   活跃 agent: recon
 * [recon] 侦察完成，发现 52 个子域名，18 个活跃 IP
 * [supervisor] [决策] delegate_vuln_scan
 * 推理: 侦察完成，启动漏洞扫描
 * ```
 *
 * ### 查看 agent 日志
 * 每个 agent 的详细日志在 session 目录：
 * ```
 * sessions/example.com_20260415_120000/
 *   recon_log.txt          # agent 执行日志
 *   recon_context.json     # 输入上下文
 *   recon_done.json        # 输出结果
 * ```
 *
 * ### 查看 tmux 会话
 * ```bash
 * tmux list-sessions
 * tmux attach -t ovogo-recon-1234567890
 * ```
 *
 * ## 未来扩展
 *
 * 1. **并行 worker** - 同时启动多个 agent（recon + vuln-scan）
 * 2. **人工介入节点** - 在关键决策点暂停等待用户确认
 * 3. **持久化状态** - 支持断点续传
 * 4. **可视化** - 实时显示状态图执行流程
 * 5. **REPL 支持** - 在 REPL 中使用 LangGraph
 */
