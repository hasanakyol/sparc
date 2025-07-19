import { Pool, PoolConfig, Client } from 'pg'
import { drizzle, PostgresJsDatabase } from 'drizzle-orm/postgres-js'
import postgres from 'postgres'
import { logger } from '@sparc/shared/utils/logger'

export interface DatabasePoolConfig {
  // Connection settings
  connectionString?: string
  host?: string
  port?: number
  database?: string
  user?: string
  password?: string
  
  // Pool settings
  min?: number // Minimum pool size
  max?: number // Maximum pool size
  idleTimeoutMillis?: number
  connectionTimeoutMillis?: number
  statementTimeout?: number
  queryTimeout?: number
  
  // PgBouncer optimizations
  pgBouncer?: boolean
  preparedStatements?: boolean
  
  // Performance settings
  ssl?: boolean | { rejectUnauthorized: boolean }
  keepAlive?: boolean
  keepAliveInitialDelayMillis?: number
  
  // Read replica configuration
  readReplicas?: Array<{
    connectionString: string
    weight?: number // Weight for load balancing
  }>
}

export interface QueryOptions {
  timeout?: number
  priority?: 'high' | 'normal' | 'low'
  useReadReplica?: boolean
  retries?: number
  retryDelay?: number
}

/**
 * Enhanced database connection pool with performance optimizations
 */
export class DatabaseConnectionPool {
  private primaryPool: Pool
  private readPools: Array<{ pool: Pool; weight: number }> = []
  private drizzleInstance: PostgresJsDatabase<any>
  private config: DatabasePoolConfig
  private stats = {
    queries: 0,
    errors: 0,
    slowQueries: 0,
    connectionErrors: 0
  }
  
  constructor(config: DatabasePoolConfig) {
    this.config = config
    
    // Create primary pool configuration
    const poolConfig: PoolConfig = {
      connectionString: config.connectionString,
      host: config.host,
      port: config.port,
      database: config.database,
      user: config.user,
      password: config.password,
      
      // Pool settings optimized for performance
      min: config.min || 10,
      max: config.max || 50,
      idleTimeoutMillis: config.idleTimeoutMillis || 30000,
      connectionTimeoutMillis: config.connectionTimeoutMillis || 5000,
      
      // Statement timeout to prevent long-running queries
      statement_timeout: config.statementTimeout || 30000,
      query_timeout: config.queryTimeout || 30000,
      
      // SSL configuration
      ssl: config.ssl,
      
      // Keep alive for persistent connections
      keepAlive: config.keepAlive !== false,
      keepAliveInitialDelayMillis: config.keepAliveInitialDelayMillis || 10000,
      
      // PgBouncer compatibility
      ...( config.pgBouncer ? {
        // Disable prepared statements for PgBouncer transaction mode
        statement_timeout: undefined,
        query_timeout: undefined,
        prepared_statements: false
      } : {})
    }
    
    // Create primary pool
    this.primaryPool = new Pool(poolConfig)
    
    // Set up event handlers
    this.setupPoolEventHandlers(this.primaryPool, 'primary')
    
    // Create read replica pools
    if (config.readReplicas && config.readReplicas.length > 0) {
      this.setupReadReplicas(config.readReplicas)
    }
    
    // Create Drizzle instance for ORM operations
    this.setupDrizzle()
  }
  
  /**
   * Set up read replica connection pools
   */
  private setupReadReplicas(replicas: DatabasePoolConfig['readReplicas']): void {
    if (!replicas) return
    
    for (const replica of replicas) {
      const replicaConfig: PoolConfig = {
        connectionString: replica.connectionString,
        min: this.config.min || 5,
        max: this.config.max || 25,
        idleTimeoutMillis: this.config.idleTimeoutMillis || 30000,
        connectionTimeoutMillis: this.config.connectionTimeoutMillis || 5000,
        ssl: this.config.ssl,
        keepAlive: true,
        keepAliveInitialDelayMillis: 10000
      }
      
      const pool = new Pool(replicaConfig)
      this.setupPoolEventHandlers(pool, `replica-${this.readPools.length}`)
      
      this.readPools.push({
        pool,
        weight: replica.weight || 1
      })
    }
    
    logger.info(`Set up ${this.readPools.length} read replica pools`)
  }
  
  /**
   * Set up Drizzle ORM instance
   */
  private setupDrizzle(): void {
    const sql = postgres(this.config.connectionString || '', {
      max: this.config.max || 50,
      idle_timeout: (this.config.idleTimeoutMillis || 30000) / 1000,
      connect_timeout: (this.config.connectionTimeoutMillis || 5000) / 1000,
      
      // Performance optimizations
      prepare: !this.config.pgBouncer, // Disable prepared statements for PgBouncer
      
      // Transform options for better performance
      transform: {
        column: (column: string) => column,
        value: (value: any) => value,
        row: (row: any) => row
      },
      
      // Connection options
      ssl: this.config.ssl,
      
      // Error handling
      onnotice: (notice) => {
        logger.debug('PostgreSQL notice:', notice)
      }
    })
    
    this.drizzleInstance = drizzle(sql)
  }
  
  /**
   * Set up pool event handlers for monitoring
   */
  private setupPoolEventHandlers(pool: Pool, name: string): void {
    pool.on('connect', (client) => {
      logger.debug(`[${name}] New client connected`)
      
      // Set session parameters for performance
      client.query('SET statement_timeout = $1', [this.config.statementTimeout || 30000])
      client.query('SET lock_timeout = $1', [10000])
      client.query('SET idle_in_transaction_session_timeout = $1', [60000])
    })
    
    pool.on('error', (err, client) => {
      logger.error(`[${name}] Pool error:`, err)
      this.stats.connectionErrors++
    })
    
    pool.on('remove', (client) => {
      logger.debug(`[${name}] Client removed from pool`)
    })
  }
  
  /**
   * Execute a query with automatic pool selection and retry logic
   */
  async query<T = any>(
    text: string,
    values?: any[],
    options?: QueryOptions
  ): Promise<{ rows: T[]; rowCount: number }> {
    const startTime = Date.now()
    const timeout = options?.timeout || this.config.queryTimeout || 30000
    const retries = options?.retries || 1
    const retryDelay = options?.retryDelay || 100
    
    // Select appropriate pool
    const pool = this.selectPool(options?.useReadReplica)
    
    let lastError: Error | null = null
    
    for (let attempt = 0; attempt < retries; attempt++) {
      try {
        // Get client from pool
        const client = await pool.connect()
        
        try {
          // Set query timeout
          await client.query('SET statement_timeout = $1', [timeout])
          
          // Execute query
          const result = await client.query(text, values)
          
          // Update statistics
          this.stats.queries++
          const duration = Date.now() - startTime
          if (duration > 1000) {
            this.stats.slowQueries++
            logger.warn(`Slow query detected (${duration}ms):`, text)
          }
          
          return result
        } finally {
          // Release client back to pool
          client.release()
        }
      } catch (error) {
        lastError = error as Error
        this.stats.errors++
        
        logger.error(`Query error (attempt ${attempt + 1}/${retries}):`, error)
        
        // Check if error is retryable
        if (this.isRetryableError(error)) {
          if (attempt < retries - 1) {
            await this.delay(retryDelay * Math.pow(2, attempt)) // Exponential backoff
            continue
          }
        }
        
        throw error
      }
    }
    
    throw lastError || new Error('Query failed after all retries')
  }
  
  /**
   * Execute multiple queries in a transaction
   */
  async transaction<T = any>(
    callback: (client: Client) => Promise<T>,
    options?: QueryOptions
  ): Promise<T> {
    const pool = this.selectPool(false) // Always use primary for transactions
    const client = await pool.connect()
    
    try {
      await client.query('BEGIN')
      
      // Set transaction timeout
      if (options?.timeout) {
        await client.query('SET statement_timeout = $1', [options.timeout])
      }
      
      const result = await callback(client)
      
      await client.query('COMMIT')
      return result
    } catch (error) {
      await client.query('ROLLBACK')
      throw error
    } finally {
      client.release()
    }
  }
  
  /**
   * Execute a batch of queries efficiently
   */
  async batch<T = any>(
    queries: Array<{ text: string; values?: any[] }>,
    options?: QueryOptions
  ): Promise<T[]> {
    return this.transaction(async (client) => {
      const results: T[] = []
      
      for (const query of queries) {
        const result = await client.query(query.text, query.values)
        results.push(result.rows)
      }
      
      return results
    }, options)
  }
  
  /**
   * Get Drizzle ORM instance for type-safe queries
   */
  getDrizzle(): PostgresJsDatabase<any> {
    return this.drizzleInstance
  }
  
  /**
   * Select appropriate pool based on query type
   */
  private selectPool(useReadReplica?: boolean): Pool {
    // Use primary for writes or if no replicas available
    if (!useReadReplica || this.readPools.length === 0) {
      return this.primaryPool
    }
    
    // Select read replica using weighted random selection
    const totalWeight = this.readPools.reduce((sum, p) => sum + p.weight, 0)
    let random = Math.random() * totalWeight
    
    for (const replica of this.readPools) {
      random -= replica.weight
      if (random <= 0) {
        return replica.pool
      }
    }
    
    // Fallback to first replica
    return this.readPools[0].pool
  }
  
  /**
   * Check if error is retryable
   */
  private isRetryableError(error: any): boolean {
    const retryableCodes = [
      '40001', // serialization_failure
      '40P01', // deadlock_detected
      '08000', // connection_exception
      '08006', // connection_failure
      '57P03', // cannot_connect_now
      '58000', // system_error
      '58030', // io_error
      '53000', // insufficient_resources
      '53100', // disk_full
      '53200', // out_of_memory
      '53300'  // too_many_connections
    ]
    
    return error?.code && retryableCodes.includes(error.code)
  }
  
  /**
   * Get pool statistics
   */
  getStats(): {
    primary: { total: number; idle: number; waiting: number }
    replicas: Array<{ total: number; idle: number; waiting: number }>
    queries: typeof this.stats
  } {
    return {
      primary: {
        total: this.primaryPool.totalCount,
        idle: this.primaryPool.idleCount,
        waiting: this.primaryPool.waitingCount
      },
      replicas: this.readPools.map(({ pool }) => ({
        total: pool.totalCount,
        idle: pool.idleCount,
        waiting: pool.waitingCount
      })),
      queries: { ...this.stats }
    }
  }
  
  /**
   * Health check for all pools
   */
  async healthCheck(): Promise<{
    primary: boolean
    replicas: boolean[]
    overall: boolean
  }> {
    const results = {
      primary: false,
      replicas: [] as boolean[],
      overall: false
    }
    
    try {
      // Check primary
      await this.primaryPool.query('SELECT 1')
      results.primary = true
      
      // Check replicas
      for (const { pool } of this.readPools) {
        try {
          await pool.query('SELECT 1')
          results.replicas.push(true)
        } catch {
          results.replicas.push(false)
        }
      }
      
      results.overall = results.primary && 
        (results.replicas.length === 0 || results.replicas.some(r => r))
    } catch (error) {
      logger.error('Health check failed:', error)
    }
    
    return results
  }
  
  /**
   * Close all connections
   */
  async close(): Promise<void> {
    await this.primaryPool.end()
    
    for (const { pool } of this.readPools) {
      await pool.end()
    }
    
    logger.info('All database connections closed')
  }
  
  // Helper methods
  
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms))
  }
}

// Factory function
export function createDatabasePool(config: DatabasePoolConfig): DatabaseConnectionPool {
  return new DatabaseConnectionPool(config)
}

// Default configuration for different environments
export const defaultPoolConfigs = {
  development: {
    min: 2,
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000
  },
  production: {
    min: 10,
    max: 50,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
    statementTimeout: 30000,
    pgBouncer: true,
    ssl: { rejectUnauthorized: false }
  }
}