import { logger } from '../logger';

export interface RetryOptions {
  maxAttempts?: number;
  initialDelay?: number;
  maxDelay?: number;
  factor?: number;
  jitter?: boolean;
  retryCondition?: (error: Error) => boolean;
  onRetry?: (error: Error, attempt: number) => void;
}

export interface RetryResult<T> {
  result?: T;
  error?: Error;
  attempts: number;
  totalTime: number;
}

/**
 * Retry a function with exponential backoff
 */
export async function retry<T>(
  fn: () => Promise<T>,
  options: RetryOptions = {}
): Promise<T> {
  const {
    maxAttempts = 3,
    initialDelay = 1000,
    maxDelay = 30000,
    factor = 2,
    jitter = true,
    retryCondition = isRetryableError,
    onRetry
  } = options;

  let lastError: Error;
  const startTime = Date.now();

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;
      
      // Check if we should retry
      if (attempt === maxAttempts || !retryCondition(lastError)) {
        throw lastError;
      }

      // Calculate delay with exponential backoff
      let delay = Math.min(initialDelay * Math.pow(factor, attempt - 1), maxDelay);
      
      // Add jitter to prevent thundering herd
      if (jitter) {
        delay = delay * (0.5 + Math.random() * 0.5);
      }

      // Log retry attempt
      logger.warn('Retrying operation', {
        attempt,
        maxAttempts,
        delay,
        error: lastError.message
      });

      // Call retry callback if provided
      if (onRetry) {
        onRetry(lastError, attempt);
      }

      // Wait before retrying
      await sleep(delay);
    }
  }

  throw lastError!;
}

/**
 * Retry with custom backoff strategy
 */
export async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  backoffFn: (attempt: number) => number,
  maxAttempts: number = 3,
  retryCondition: (error: Error) => boolean = isRetryableError
): Promise<T> {
  let lastError: Error;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;
      
      if (attempt === maxAttempts || !retryCondition(lastError)) {
        throw lastError;
      }

      const delay = backoffFn(attempt);
      await sleep(delay);
    }
  }

  throw lastError!;
}

/**
 * Retry with timeout
 */
export async function retryWithTimeout<T>(
  fn: () => Promise<T>,
  timeout: number,
  options: RetryOptions = {}
): Promise<T> {
  return Promise.race([
    retry(fn, options),
    rejectAfterTimeout<T>(timeout, 'Operation timeout')
  ]);
}

/**
 * Bulk retry operations
 */
export async function retryBulk<T>(
  operations: Array<() => Promise<T>>,
  options: RetryOptions = {}
): Promise<Array<RetryResult<T>>> {
  return Promise.all(
    operations.map(async (op) => {
      const startTime = Date.now();
      let attempts = 0;
      
      try {
        const result = await retry(() => {
          attempts++;
          return op();
        }, options);
        
        return {
          result,
          attempts,
          totalTime: Date.now() - startTime
        };
      } catch (error) {
        return {
          error: error as Error,
          attempts,
          totalTime: Date.now() - startTime
        };
      }
    })
  );
}

/**
 * Check if error is retryable
 */
export function isRetryableError(error: Error): boolean {
  // Network errors
  if (error.message?.includes('ECONNREFUSED') ||
      error.message?.includes('ETIMEDOUT') ||
      error.message?.includes('ECONNRESET') ||
      error.message?.includes('ENETUNREACH')) {
    return true;
  }

  // HTTP errors
  const httpError = error as any;
  if (httpError.status) {
    // Retry on 5xx errors and specific 4xx errors
    return httpError.status >= 500 || 
           httpError.status === 429 || // Too Many Requests
           httpError.status === 408;    // Request Timeout
  }

  // Database errors
  if (error.name === 'PrismaClientKnownRequestError') {
    const prismaError = error as any;
    // Retry on connection and timeout errors
    return ['P1001', 'P1002', 'P1008', 'P1017'].includes(prismaError.code);
  }

  // Default: don't retry
  return false;
}

/**
 * Sleep for specified milliseconds
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Reject after timeout
 */
function rejectAfterTimeout<T>(ms: number, message: string): Promise<T> {
  return new Promise((_, reject) => {
    setTimeout(() => reject(new Error(message)), ms);
  });
}

/**
 * Decorator for retry logic
 */
export function Retryable(options: RetryOptions = {}) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;
    
    descriptor.value = async function (...args: any[]) {
      return retry(() => originalMethod.apply(this, args), {
        ...options,
        onRetry: (error, attempt) => {
          logger.warn(`Retrying ${target.constructor.name}.${propertyKey}`, {
            attempt,
            error: error.message
          });
          options.onRetry?.(error, attempt);
        }
      });
    };
    
    return descriptor;
  };
}

/**
 * Backoff strategies
 */
export const BackoffStrategies = {
  /**
   * Exponential backoff
   */
  exponential: (base: number = 1000, factor: number = 2, max: number = 30000) => {
    return (attempt: number) => Math.min(base * Math.pow(factor, attempt - 1), max);
  },

  /**
   * Linear backoff
   */
  linear: (delay: number = 1000) => {
    return (attempt: number) => delay * attempt;
  },

  /**
   * Constant backoff
   */
  constant: (delay: number = 1000) => {
    return () => delay;
  },

  /**
   * Fibonacci backoff
   */
  fibonacci: (base: number = 1000, max: number = 30000) => {
    const fib = [1, 1];
    return (attempt: number) => {
      while (fib.length <= attempt) {
        fib.push(fib[fib.length - 1] + fib[fib.length - 2]);
      }
      return Math.min(base * fib[attempt - 1], max);
    };
  }
};

/**
 * Retry policy for different scenarios
 */
export const RetryPolicies = {
  /**
   * Database operations
   */
  database: {
    maxAttempts: 3,
    initialDelay: 100,
    maxDelay: 1000,
    factor: 2,
    jitter: true,
    retryCondition: (error: Error) => {
      return isRetryableError(error) || error.message?.includes('deadlock');
    }
  },

  /**
   * External API calls
   */
  api: {
    maxAttempts: 5,
    initialDelay: 1000,
    maxDelay: 10000,
    factor: 2,
    jitter: true
  },

  /**
   * Internal service calls
   */
  service: {
    maxAttempts: 3,
    initialDelay: 500,
    maxDelay: 5000,
    factor: 1.5,
    jitter: true
  },

  /**
   * Quick retry for transient errors
   */
  quick: {
    maxAttempts: 2,
    initialDelay: 100,
    maxDelay: 200,
    factor: 1,
    jitter: false
  }
};