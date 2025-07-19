import { EventEmitter } from 'events';
import { logger } from '../logger';

export interface CircuitBreakerOptions {
  name: string;
  failureThreshold?: number;
  resetTimeout?: number;
  monitoringPeriod?: number;
  halfOpenMaxAttempts?: number;
  timeout?: number;
  volumeThreshold?: number;
  errorFilter?: (error: Error) => boolean;
}

export enum CircuitState {
  CLOSED = 'CLOSED',
  OPEN = 'OPEN',
  HALF_OPEN = 'HALF_OPEN'
}

export interface CircuitBreakerStats {
  state: CircuitState;
  failures: number;
  successes: number;
  rejections: number;
  lastFailureTime?: Date;
  nextAttemptTime?: Date;
}

export class CircuitBreaker extends EventEmitter {
  private name: string;
  private state: CircuitState = CircuitState.CLOSED;
  private failures = 0;
  private successes = 0;
  private rejections = 0;
  private lastFailureTime?: Date;
  private nextAttemptTime?: Date;
  private halfOpenAttempts = 0;
  private requestVolume = 0;
  private volumeResetTimer?: NodeJS.Timeout;

  private readonly failureThreshold: number;
  private readonly resetTimeout: number;
  private readonly monitoringPeriod: number;
  private readonly halfOpenMaxAttempts: number;
  private readonly timeout: number;
  private readonly volumeThreshold: number;
  private readonly errorFilter: (error: Error) => boolean;

  constructor(options: CircuitBreakerOptions) {
    super();
    this.name = options.name;
    this.failureThreshold = options.failureThreshold || 5;
    this.resetTimeout = options.resetTimeout || 60000; // 60 seconds
    this.monitoringPeriod = options.monitoringPeriod || 60000; // 60 seconds
    this.halfOpenMaxAttempts = options.halfOpenMaxAttempts || 3;
    this.timeout = options.timeout || 30000; // 30 seconds
    this.volumeThreshold = options.volumeThreshold || 10;
    this.errorFilter = options.errorFilter || (() => true);

    this.startVolumeReset();
  }

  /**
   * Execute a function with circuit breaker protection
   */
  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === CircuitState.OPEN) {
      if (!this.canAttemptReset()) {
        this.rejections++;
        this.emit('rejected', { name: this.name });
        throw new Error(`Circuit breaker ${this.name} is OPEN`);
      }
      this.toHalfOpen();
    }

    this.requestVolume++;

    try {
      const result = await this.executeWithTimeout(fn);
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure(error as Error);
      throw error;
    }
  }

  /**
   * Execute function with timeout
   */
  private async executeWithTimeout<T>(fn: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`Circuit breaker ${this.name} timeout after ${this.timeout}ms`));
      }, this.timeout);

      fn()
        .then(result => {
          clearTimeout(timer);
          resolve(result);
        })
        .catch(error => {
          clearTimeout(timer);
          reject(error);
        });
    });
  }

  /**
   * Handle successful execution
   */
  private onSuccess(): void {
    this.failures = 0;
    this.successes++;

    if (this.state === CircuitState.HALF_OPEN) {
      this.halfOpenAttempts++;
      if (this.halfOpenAttempts >= this.halfOpenMaxAttempts) {
        this.toClosed();
      }
    }

    this.emit('success', { name: this.name, state: this.state });
  }

  /**
   * Handle failed execution
   */
  private onFailure(error: Error): void {
    if (!this.errorFilter(error)) {
      // Error should not trigger circuit breaker
      return;
    }

    this.failures++;
    this.lastFailureTime = new Date();

    if (this.state === CircuitState.HALF_OPEN) {
      this.toOpen();
    } else if (this.state === CircuitState.CLOSED) {
      if (this.failures >= this.failureThreshold) {
        if (this.requestVolume >= this.volumeThreshold) {
          this.toOpen();
        }
      }
    }

    this.emit('failure', { name: this.name, state: this.state, error });
    logger.warn(`Circuit breaker ${this.name} failure`, {
      failures: this.failures,
      state: this.state,
      error: error.message
    });
  }

  /**
   * Transition to OPEN state
   */
  private toOpen(): void {
    this.state = CircuitState.OPEN;
    this.nextAttemptTime = new Date(Date.now() + this.resetTimeout);
    this.halfOpenAttempts = 0;
    
    this.emit('open', { name: this.name });
    logger.error(`Circuit breaker ${this.name} is now OPEN`, {
      failures: this.failures,
      nextAttemptTime: this.nextAttemptTime
    });
  }

  /**
   * Transition to HALF_OPEN state
   */
  private toHalfOpen(): void {
    this.state = CircuitState.HALF_OPEN;
    this.halfOpenAttempts = 0;
    
    this.emit('halfOpen', { name: this.name });
    logger.info(`Circuit breaker ${this.name} is now HALF_OPEN`);
  }

  /**
   * Transition to CLOSED state
   */
  private toClosed(): void {
    this.state = CircuitState.CLOSED;
    this.failures = 0;
    this.nextAttemptTime = undefined;
    
    this.emit('closed', { name: this.name });
    logger.info(`Circuit breaker ${this.name} is now CLOSED`);
  }

  /**
   * Check if we can attempt to reset from OPEN state
   */
  private canAttemptReset(): boolean {
    return this.nextAttemptTime ? new Date() >= this.nextAttemptTime : false;
  }

  /**
   * Start volume reset timer
   */
  private startVolumeReset(): void {
    this.volumeResetTimer = setInterval(() => {
      this.requestVolume = 0;
    }, this.monitoringPeriod);
  }

  /**
   * Get current statistics
   */
  getStats(): CircuitBreakerStats {
    return {
      state: this.state,
      failures: this.failures,
      successes: this.successes,
      rejections: this.rejections,
      lastFailureTime: this.lastFailureTime,
      nextAttemptTime: this.nextAttemptTime
    };
  }

  /**
   * Reset the circuit breaker
   */
  reset(): void {
    this.state = CircuitState.CLOSED;
    this.failures = 0;
    this.successes = 0;
    this.rejections = 0;
    this.lastFailureTime = undefined;
    this.nextAttemptTime = undefined;
    this.halfOpenAttempts = 0;
    this.requestVolume = 0;
    
    this.emit('reset', { name: this.name });
    logger.info(`Circuit breaker ${this.name} has been reset`);
  }

  /**
   * Cleanup resources
   */
  destroy(): void {
    if (this.volumeResetTimer) {
      clearInterval(this.volumeResetTimer);
    }
    this.removeAllListeners();
  }
}

/**
 * Circuit breaker factory
 */
export class CircuitBreakerFactory {
  private static breakers = new Map<string, CircuitBreaker>();

  /**
   * Create or get a circuit breaker
   */
  static create(options: CircuitBreakerOptions): CircuitBreaker {
    const existing = this.breakers.get(options.name);
    if (existing) {
      return existing;
    }

    const breaker = new CircuitBreaker(options);
    this.breakers.set(options.name, breaker);
    return breaker;
  }

  /**
   * Get all circuit breakers
   */
  static getAll(): Map<string, CircuitBreaker> {
    return new Map(this.breakers);
  }

  /**
   * Get statistics for all breakers
   */
  static getAllStats(): Record<string, CircuitBreakerStats> {
    const stats: Record<string, CircuitBreakerStats> = {};
    this.breakers.forEach((breaker, name) => {
      stats[name] = breaker.getStats();
    });
    return stats;
  }

  /**
   * Reset all circuit breakers
   */
  static resetAll(): void {
    this.breakers.forEach(breaker => breaker.reset());
  }

  /**
   * Destroy all circuit breakers
   */
  static destroyAll(): void {
    this.breakers.forEach(breaker => breaker.destroy());
    this.breakers.clear();
  }
}

/**
 * Decorator for circuit breaker protection
 */
export function CircuitBreakerProtected(options: Omit<CircuitBreakerOptions, 'name'>) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;
    const breakerName = `${target.constructor.name}.${propertyKey}`;
    
    descriptor.value = async function (...args: any[]) {
      const breaker = CircuitBreakerFactory.create({
        ...options,
        name: breakerName
      });
      
      return breaker.execute(() => originalMethod.apply(this, args));
    };
    
    return descriptor;
  };
}