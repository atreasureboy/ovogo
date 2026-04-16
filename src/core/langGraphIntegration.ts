/**
 * 集成 LangGraph 到主入口
 *
 * 添加 --langgraph 标志，启用新的状态图引擎。
 */

import { LangGraphEngine } from '../src/core/langGraphEngine.js'

// 在 main() 函数中添加 LangGraph 模式检测
// 在 config 构建之后，engine 创建之前插入以下代码：

/**
 * 检测是否使用 LangGraph 模式
 *
 * 触发条件：
 * 1. 环境变量 OVOGO_LANGGRAPH=true
 * 2. 命令行参数 --langgraph
 * 3. settings.json 中配置 "useLangGraph": true
 */
export function shouldUseLangGraph(
  argv: string[],
  settings: { useLangGraph?: boolean },
): boolean {
  // 环境变量
  if (process.env.OVOGO_LANGGRAPH === 'true' || process.env.OVOGO_LANGGRAPH === '1') {
    return true
  }

  // 命令行参数
  if (argv.includes('--langgraph')) {
    return true
  }

  // 配置文件
  if (settings.useLangGraph === true) {
    return true
  }

  return false
}

/**
 * 创建 LangGraph 引擎并执行任务
 */
export async function runWithLangGraph(params: {
  task: string
  model: string
  apiKey: string
  baseURL?: string
  sessionDir: string
  primaryTarget?: string
  cwd: string
  renderer: any
}): Promise<void> {
  const { task, model, apiKey, baseURL, sessionDir, primaryTarget, cwd, renderer } = params

  renderer.info('[模式] LangGraph 状态图引擎')

  const langGraphEngine = new LangGraphEngine(
    {
      model,
      apiKey,
      baseURL,
      sessionDir,
      primaryTarget,
      cwd,
    },
    renderer,
  )

  await langGraphEngine.runTask(task)
}

// 使用示例（在 bin/ovogogogo.ts 的 main() 函数中）：
/*

  // ... 现有的配置加载代码 ...

  // 检测是否使用 LangGraph
  const useLangGraph = shouldUseLangGraph(process.argv, settings)

  if (useLangGraph) {
    renderer.info('[模式] LangGraph 状态图引擎')

    // 单次任务模式
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

    // REPL 模式（暂不支持，提示用户）
    renderer.warn('LangGraph 模式暂不支持 REPL，请使用单次任务模式')
    renderer.info('示例: ovogogogo --langgraph "对 example.com 进行渗透测试"')
    process.exit(1)
  }

  // 原有的 ExecutionEngine 逻辑
  const engine = new ExecutionEngine(config, renderer)
  // ...

*/
