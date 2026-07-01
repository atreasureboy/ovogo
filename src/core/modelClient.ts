import OpenAI from 'openai'
import type { OpenAIMessage, ToolDefinition } from './types.js'

export type ChatStreamChunk = OpenAI.Chat.ChatCompletionChunk
export type ModelMessageContent =
  | string
  | Array<
      | { type: 'text'; text: string }
      | { type: 'image_url'; image_url: { url: string; detail?: 'auto' | 'low' | 'high' } }
    >

export interface ChatStreamRequest {
  model: string
  systemPrompt: string
  messages: OpenAIMessage[]
  tools: ToolDefinition[]
  signal?: AbortSignal
  temperature?: number
  maxTokens?: number
}

export interface ModelClient {
  streamChat(request: ChatStreamRequest): Promise<AsyncIterable<ChatStreamChunk>>
  completeText(request: TextCompletionRequest): Promise<string>
}

export interface TextCompletionRequest {
  model: string
  messages: Array<{ role: 'system' | 'user' | 'assistant'; content: ModelMessageContent }>
  signal?: AbortSignal
  temperature?: number
  maxTokens?: number
  responseFormat?: 'json_object'
}

export class OpenAICompatibleModelClient implements ModelClient {
  constructor(private readonly client: OpenAI) {}

  static fromConfig(config: { apiKey: string; baseURL?: string }): OpenAICompatibleModelClient {
    return new OpenAICompatibleModelClient(new OpenAI({
      apiKey: config.apiKey,
      baseURL: config.baseURL,
    }))
  }

  streamChat(request: ChatStreamRequest): Promise<AsyncIterable<ChatStreamChunk>> {
    return this.client.chat.completions.create(
      {
        model: request.model,
        messages: [
          { role: 'system', content: request.systemPrompt },
          ...(request.messages as OpenAI.Chat.ChatCompletionMessageParam[]),
        ],
        tools: request.tools as OpenAI.Chat.ChatCompletionTool[],
        tool_choice: 'auto',
        temperature: request.temperature ?? 0,
        max_tokens: request.maxTokens ?? 8192,
        stream: true,
      },
      { signal: request.signal },
    )
  }

  async completeText(request: TextCompletionRequest): Promise<string> {
    const response = await this.client.chat.completions.create(
      {
        model: request.model,
        messages: request.messages as OpenAI.Chat.ChatCompletionMessageParam[],
        temperature: request.temperature ?? 0,
        max_tokens: request.maxTokens,
        response_format: request.responseFormat ? { type: request.responseFormat } : undefined,
      },
      { signal: request.signal },
    )

    return response.choices[0]?.message?.content?.trim() ?? ''
  }
}
