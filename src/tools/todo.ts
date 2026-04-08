/**
 * TodoWrite — task list management
 * Reference: src/tools/TodoWriteTool/
 *
 * Lets the LLM create and manage a checklist of subtasks.
 * Displayed in the terminal as ✓/○ items.
 * Stored in-process (per-session) — not persisted to disk.
 */

import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'

export interface TodoItem {
  id: string
  content: string
  status: 'pending' | 'in_progress' | 'completed'
  priority: 'high' | 'medium' | 'low'
}

// Module-level store — shared across all tool invocations in a session
let todoList: TodoItem[] = []

export function getTodoList(): TodoItem[] {
  return todoList
}

export function renderTodoList(): string {
  if (todoList.length === 0) return '(no tasks)'
  return todoList
    .map((item) => {
      const icon =
        item.status === 'completed' ? '✓' :
        item.status === 'in_progress' ? '◆' : '○'
      const pri = item.priority === 'high' ? '[H]' : item.priority === 'low' ? '[L]' : '   '
      return `${icon} ${pri} ${item.content}`
    })
    .join('\n')
}

export class TodoWriteTool implements Tool {
  name = 'TodoWrite'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'TodoWrite',
      description: `Manage a task checklist for the current session.

Use this tool to:
- Break a complex task into subtasks and track progress
- Mark tasks as in_progress when starting them
- Mark tasks as completed when done

The list is displayed to the user and helps them track what you're doing.

Operations:
- "create": replace the entire list with new todos
- "update": update status of specific todo(s) by id

Always update status as you work: set in_progress before starting a task, completed when done.`,
      parameters: {
        type: 'object',
        properties: {
          todos: {
            type: 'array',
            description: 'List of todo items (for create operation, or updated items for update)',
            items: {
              type: 'object',
              properties: {
                id: { type: 'string', description: 'Unique ID (e.g. "1", "2", "setup-deps")' },
                content: { type: 'string', description: 'Task description' },
                status: {
                  type: 'string',
                  enum: ['pending', 'in_progress', 'completed'],
                  description: 'Task status',
                },
                priority: {
                  type: 'string',
                  enum: ['high', 'medium', 'low'],
                  description: 'Task priority',
                },
              },
              required: ['id', 'content', 'status', 'priority'],
            },
          },
        },
        required: ['todos'],
      },
    },
  }

  async execute(input: Record<string, unknown>, _context: ToolContext): Promise<ToolResult> {
    const todos = input.todos as TodoItem[] | undefined

    if (!Array.isArray(todos)) {
      return { content: 'Error: todos must be an array', isError: true }
    }

    // Validate each item
    for (const item of todos) {
      if (!item.id || !item.content || !item.status || !item.priority) {
        return {
          content: `Error: each todo must have id, content, status, and priority. Got: ${JSON.stringify(item)}`,
          isError: true,
        }
      }
    }

    // Update: merge by id. If id doesn't exist, add it.
    // If todos covers ALL existing ids, treat as replace.
    const existingIds = new Set(todoList.map(t => t.id))
    const incomingIds = new Set(todos.map(t => t.id))
    const allExistingCovered = todoList.every(t => incomingIds.has(t.id))

    if (todoList.length === 0 || allExistingCovered) {
      // Full replace
      todoList = todos.map(t => ({ ...t }))
    } else {
      // Partial update — merge by id
      for (const updated of todos) {
        const existing = todoList.find(t => t.id === updated.id)
        if (existing) {
          existing.status = updated.status
          existing.priority = updated.priority
          existing.content = updated.content
        } else {
          todoList.push({ ...updated })
        }
      }
    }

    const rendered = renderTodoList()
    return {
      content: `Tasks updated:\n${rendered}`,
      isError: false,
    }
  }
}
