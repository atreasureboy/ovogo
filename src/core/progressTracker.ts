/**
 * Progress Tracker for long-running tools
 * Supports progress tracking and interruption recovery
 */

export interface ProgressData {
  taskId: string;
  toolName: string;
  input: Record<string, unknown>;
  progress: number; // 0-100
  status: 'running' | 'paused' | 'completed' | 'failed';
  startTime: number;
  lastUpdate: number;
  estimatedTimeRemaining?: number; // in seconds
  output?: string;
  error?: string;
  recoveryData?: Record<string, unknown>; // Data needed for recovery
}

export class ProgressTracker {
  private tasks: Map<string, ProgressData> = new Map();
  private updateInterval: NodeJS.Timeout | null = null;

  /**
   * Start tracking a task
   */
  start(taskId: string, toolName: string, input: Record<string, unknown>): void {
    this.tasks.set(taskId, {
      taskId,
      toolName,
      input,
      progress: 0,
      status: 'running',
      startTime: Date.now(),
      lastUpdate: Date.now()
    });

    // Start periodic updates if not already running
    if (!this.updateInterval) {
      this.updateInterval = setInterval(() => this.cleanupStaleTasks(), 5 * 60 * 1000).unref(); // Every 5 minutes
    }
  }

  /**
   * Update task progress
   */
  update(taskId: string, progress: number, recoveryData?: Record<string, unknown>): void {
    const task = this.tasks.get(taskId);
    if (task) {
      const now = Date.now();
      const elapsed = (now - task.startTime) / 1000;
      const estimatedTotal = (elapsed / (progress / 100)) || 0;
      const estimatedRemaining = Math.max(0, estimatedTotal - elapsed);

      this.tasks.set(taskId, {
        ...task,
        progress: Math.min(100, Math.max(0, progress)),
        lastUpdate: now,
        estimatedTimeRemaining: estimatedRemaining,
        recoveryData: recoveryData
      });
    }
  }

  /**
   * Pause a task
   */
  pause(taskId: string): void {
    const task = this.tasks.get(taskId);
    if (task) {
      this.tasks.set(taskId, {
        ...task,
        status: 'paused',
        lastUpdate: Date.now()
      });
    }
  }

  /**
   * Resume a task
   */
  resume(taskId: string): void {
    const task = this.tasks.get(taskId);
    if (task) {
      this.tasks.set(taskId, {
        ...task,
        status: 'running',
        lastUpdate: Date.now()
      });
    }
  }

  /**
   * Complete a task
   */
  complete(taskId: string, output?: string): void {
    const task = this.tasks.get(taskId);
    if (task) {
      this.tasks.set(taskId, {
        ...task,
        progress: 100,
        status: 'completed',
        lastUpdate: Date.now(),
        output
      });
    }
  }

  /**
   * Fail a task
   */
  fail(taskId: string, error: string): void {
    const task = this.tasks.get(taskId);
    if (task) {
      this.tasks.set(taskId, {
        ...task,
        status: 'failed',
        lastUpdate: Date.now(),
        error
      });
    }
  }

  /**
   * Get task progress
   */
  getProgress(taskId: string): ProgressData | undefined {
    return this.tasks.get(taskId);
  }

  /**
   * Get all tasks
   */
  getAllTasks(): ProgressData[] {
    return Array.from(this.tasks.values());
  }

  /**
   * Remove a task
   */
  remove(taskId: string): boolean {
    return this.tasks.delete(taskId);
  }

  /**
   * Clean up stale tasks (completed or failed more than 24 hours ago)
   */
  private cleanupStaleTasks(): void {
    const now = Date.now();
    const staleThreshold = 24 * 60 * 60 * 1000; // 24 hours

    for (const [taskId, task] of this.tasks.entries()) {
      if ((task.status === 'completed' || task.status === 'failed') && 
          now - task.lastUpdate > staleThreshold) {
        this.tasks.delete(taskId);
      }
    }

    // Stop interval if no tasks left
    if (this.tasks.size === 0 && this.updateInterval) {
      clearInterval(this.updateInterval);
      this.updateInterval = null;
    }
  }

  /**
   * Get tasks that can be recovered (paused or failed)
   */
  getRecoverableTasks(): ProgressData[] {
    return Array.from(this.tasks.values()).filter(
      task => task.status === 'paused' || task.status === 'failed'
    );
  }

  /**
   * Clear all tasks
   */
  clear(): void {
    this.tasks.clear();
    if (this.updateInterval) {
      clearInterval(this.updateInterval);
      this.updateInterval = null;
    }
  }
}
