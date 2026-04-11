/**
 * Tool Execution Cache
 * Prevents duplicate tool executions by caching results
 */

import { createHash } from 'crypto';

export interface CacheEntry {
  key: string;
  toolName: string;
  input: Record<string, unknown>;
  result: {
    content: string;
    isError: boolean;
  };
  timestamp: number;
  expiration: number; // Absolute timestamp when cache expires
}

export class ToolCache {
  private cache: Map<string, CacheEntry> = new Map();
  private defaultTTL: number; // Default time-to-live in milliseconds
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor(defaultTTL: number = 24 * 60 * 60 * 1000) { // 24 hours default
    this.defaultTTL = defaultTTL;
    this.startCleanupInterval();
  }

  /**
   * Generate a cache key based on tool name and input
   */
  private generateKey(toolName: string, input: Record<string, unknown>): string {
    const normalizedInput = this.normalizeInput(input);
    const data = `${toolName}:${JSON.stringify(normalizedInput)}`;
    return createHash('sha256').update(data).digest('hex');
  }

  /**
   * Normalize input to ensure consistent hashing
   */
  private normalizeInput(input: Record<string, unknown>): Record<string, unknown> {
    // Sort object keys to ensure consistent hashing
    if (typeof input !== 'object' || input === null) {
      return input as Record<string, unknown>;
    }

    const normalized: Record<string, unknown> = {};
    const keys = Object.keys(input).sort();
    
    for (const key of keys) {
      const value = input[key];
      if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        normalized[key] = this.normalizeInput(value as Record<string, unknown>);
      } else if (Array.isArray(value)) {
        normalized[key] = value.sort();
      } else {
        normalized[key] = value;
      }
    }
    
    return normalized;
  }

  /**
   * Get a cached result
   */
  get(toolName: string, input: Record<string, unknown>): { content: string; isError: boolean } | null {
    const key = this.generateKey(toolName, input);
    const entry = this.cache.get(key);
    
    if (!entry) {
      return null;
    }
    
    // Check if entry is expired
    if (Date.now() > entry.expiration) {
      this.cache.delete(key);
      return null;
    }
    
    return entry.result;
  }

  /**
   * Set a cached result
   */
  set(toolName: string, input: Record<string, unknown>, result: { content: string; isError: boolean }, ttl?: number): void {
    const key = this.generateKey(toolName, input);
    const expiration = Date.now() + (ttl || this.defaultTTL);
    
    this.cache.set(key, {
      key,
      toolName,
      input,
      result,
      timestamp: Date.now(),
      expiration
    });
  }

  /**
   * Delete a cached result
   */
  delete(toolName: string, input: Record<string, unknown>): boolean {
    const key = this.generateKey(toolName, input);
    return this.cache.delete(key);
  }

  /**
   * Clear the entire cache
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Clear cache for a specific tool
   */
  clearTool(toolName: string): void {
    for (const [key, entry] of this.cache.entries()) {
      if (entry.toolName === toolName) {
        this.cache.delete(key);
      }
    }
  }

  /**
   * Get cache size
   */
  size(): number {
    return this.cache.size;
  }

  /**
   * Start periodic cleanup of expired entries
   */
  private startCleanupInterval(): void {
    this.cleanupInterval = setInterval(() => this.cleanupExpired(), 30 * 60 * 1000); // Every 30 minutes
  }

  /**
   * Clean up expired cache entries
   */
  private cleanupExpired(): void {
    const now = Date.now();
    let deleted = 0;
    
    for (const [key, entry] of this.cache.entries()) {
      if (now > entry.expiration) {
        this.cache.delete(key);
        deleted++;
      }
    }
    
    // Cleanup is silent — no stdout pollution needed for housekeeping
  }

  /**
   * Stop cleanup interval
   */
  stop(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }
}
