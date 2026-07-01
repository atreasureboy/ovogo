export interface SchedulableToolCall {
  tc: {
    name: string
  }
}

export interface ToolBatch<TCall extends SchedulableToolCall> {
  safe: boolean
  calls: TCall[]
}

export interface ToolSchedulerOptions {
  /** Maximum calls in one parallel-safe batch. Values <= 0 mean no cap. */
  maxParallelBatchSize?: number
}

/**
 * Partition tool calls into execution batches while preserving model order.
 *
 * Adjacent concurrency-safe calls are grouped into one parallel batch. Stateful
 * or order-sensitive calls get their own serial batch. Safe runs can be split
 * into bounded batches to avoid unbounded Promise.all fan-out.
 */
export function partitionToolCalls<TCall extends SchedulableToolCall>(
  calls: TCall[],
  isConcurrencySafe: (toolName: string) => boolean,
  options: ToolSchedulerOptions = {},
): ToolBatch<TCall>[] {
  const batches: ToolBatch<TCall>[] = []
  const maxParallelBatchSize = Math.floor(options.maxParallelBatchSize ?? 0)

  for (const call of calls) {
    const safe = isConcurrencySafe(call.tc.name)
    const last = batches[batches.length - 1]

    if (
      last &&
      last.safe &&
      safe &&
      (maxParallelBatchSize <= 0 || last.calls.length < maxParallelBatchSize)
    ) {
      last.calls.push(call)
    } else {
      batches.push({ safe, calls: [call] })
    }
  }

  return batches
}
