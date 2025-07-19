import Redis from 'ioredis';
import { telemetry } from '@sparc/shared/telemetry';

interface ComplianceJob {
  id: string;
  type: 'scan' | 'report' | 'check' | 'export';
  tenantId: string;
  data: any;
  priority: number;
  createdAt: Date;
  attempts: number;
  maxAttempts: number;
}

export class ComplianceQueue {
  private readonly QUEUE_KEY = 'compliance:queue';
  private readonly PROCESSING_KEY = 'compliance:processing';
  private readonly DEAD_LETTER_KEY = 'compliance:dead-letter';
  private isProcessing = false;
  private processingInterval: NodeJS.Timeout | null = null;

  constructor(private redis: Redis) {}

  async start(): Promise<void> {
    this.isProcessing = true;
    
    // Process queue every 5 seconds
    this.processingInterval = setInterval(async () => {
      await this.processQueue();
    }, 5000);
  }

  async stop(): Promise<void> {
    this.isProcessing = false;
    
    if (this.processingInterval) {
      clearInterval(this.processingInterval);
      this.processingInterval = null;
    }
  }

  async addJob(job: Omit<ComplianceJob, 'id' | 'createdAt' | 'attempts'>): Promise<string> {
    return telemetry.withSpan('complianceQueue.addJob', async (span) => {
      const completeJob: ComplianceJob = {
        ...job,
        id: `job-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        createdAt: new Date(),
        attempts: 0,
        maxAttempts: job.maxAttempts || 3
      };

      span.setAttributes({
        'job.id': completeJob.id,
        'job.type': completeJob.type,
        'job.priority': completeJob.priority
      });

      // Add to priority queue (higher priority = processed first)
      await this.redis.zadd(
        this.QUEUE_KEY,
        -completeJob.priority, // Negative for descending order
        JSON.stringify(completeJob)
      );

      return completeJob.id;
    });
  }

  async getJob(jobId: string): Promise<ComplianceJob | null> {
    // Check in queue
    const jobs = await this.redis.zrange(this.QUEUE_KEY, 0, -1);
    for (const jobStr of jobs) {
      const job = JSON.parse(jobStr) as ComplianceJob;
      if (job.id === jobId) {
        return job;
      }
    }

    // Check in processing
    const processingJobs = await this.redis.hgetall(this.PROCESSING_KEY);
    for (const jobStr of Object.values(processingJobs)) {
      const job = JSON.parse(jobStr) as ComplianceJob;
      if (job.id === jobId) {
        return job;
      }
    }

    return null;
  }

  async removeJob(jobId: string): Promise<boolean> {
    const job = await this.getJob(jobId);
    if (!job) return false;

    // Remove from queue
    await this.redis.zrem(this.QUEUE_KEY, JSON.stringify(job));
    
    // Remove from processing
    await this.redis.hdel(this.PROCESSING_KEY, jobId);

    return true;
  }

  async getQueueStatus(): Promise<{
    pending: number;
    processing: number;
    deadLetter: number;
  }> {
    const [pending, processing, deadLetter] = await Promise.all([
      this.redis.zcard(this.QUEUE_KEY),
      this.redis.hlen(this.PROCESSING_KEY),
      this.redis.llen(this.DEAD_LETTER_KEY)
    ]);

    return { pending, processing, deadLetter };
  }

  async isHealthy(): Promise<boolean> {
    try {
      await this.redis.ping();
      return this.isProcessing;
    } catch {
      return false;
    }
  }

  private async processQueue(): Promise<void> {
    if (!this.isProcessing) return;

    return telemetry.withSpan('complianceQueue.processQueue', async (span) => {
      try {
        // Get highest priority job
        const results = await this.redis.zpopmax(this.QUEUE_KEY, 1);
        if (results.length === 0) return;

        const [jobStr] = results;
        const job = JSON.parse(jobStr as string) as ComplianceJob;

        span.setAttributes({
          'job.id': job.id,
          'job.type': job.type,
          'job.attempts': job.attempts
        });

        // Move to processing
        await this.redis.hset(this.PROCESSING_KEY, job.id, JSON.stringify(job));

        try {
          // Process job based on type
          await this.processJob(job);

          // Remove from processing on success
          await this.redis.hdel(this.PROCESSING_KEY, job.id);

          span.setAttribute('job.status', 'completed');
        } catch (error) {
          span.setAttribute('job.status', 'failed');
          
          // Handle job failure
          await this.handleJobFailure(job, error);
        }
      } catch (error) {
        span.setStatus({ code: 2, message: error.message });
        console.error('Error processing queue:', error);
      }
    });
  }

  private async processJob(job: ComplianceJob): Promise<void> {
    console.log(`Processing job ${job.id} of type ${job.type}`);

    switch (job.type) {
      case 'scan':
        await this.processScanJob(job);
        break;
      case 'report':
        await this.processReportJob(job);
        break;
      case 'check':
        await this.processCheckJob(job);
        break;
      case 'export':
        await this.processExportJob(job);
        break;
      default:
        throw new Error(`Unknown job type: ${job.type}`);
    }
  }

  private async processScanJob(job: ComplianceJob): Promise<void> {
    // Implement scan processing
    // This would call the security scan service
    await new Promise(resolve => setTimeout(resolve, 1000)); // Simulate work
  }

  private async processReportJob(job: ComplianceJob): Promise<void> {
    // Implement report generation
    // This would call the compliance service
    await new Promise(resolve => setTimeout(resolve, 2000)); // Simulate work
  }

  private async processCheckJob(job: ComplianceJob): Promise<void> {
    // Implement compliance check
    // This would call the compliance service
    await new Promise(resolve => setTimeout(resolve, 1500)); // Simulate work
  }

  private async processExportJob(job: ComplianceJob): Promise<void> {
    // Implement data export
    // This would call the appropriate service
    await new Promise(resolve => setTimeout(resolve, 3000)); // Simulate work
  }

  private async handleJobFailure(job: ComplianceJob, error: any): Promise<void> {
    job.attempts++;

    if (job.attempts >= job.maxAttempts) {
      // Move to dead letter queue
      await this.redis.lpush(this.DEAD_LETTER_KEY, JSON.stringify({
        ...job,
        error: error.message,
        failedAt: new Date()
      }));

      // Remove from processing
      await this.redis.hdel(this.PROCESSING_KEY, job.id);

      console.error(`Job ${job.id} moved to dead letter queue after ${job.attempts} attempts`);
    } else {
      // Retry with exponential backoff
      const delay = Math.pow(2, job.attempts) * 1000; // 2s, 4s, 8s, etc.
      
      setTimeout(async () => {
        // Remove from processing
        await this.redis.hdel(this.PROCESSING_KEY, job.id);
        
        // Re-add to queue with same priority
        await this.redis.zadd(
          this.QUEUE_KEY,
          -job.priority,
          JSON.stringify(job)
        );
      }, delay);

      console.log(`Job ${job.id} will be retried in ${delay}ms (attempt ${job.attempts})`);
    }
  }

  async getDeadLetterJobs(limit: number = 100): Promise<ComplianceJob[]> {
    const jobs = await this.redis.lrange(this.DEAD_LETTER_KEY, 0, limit - 1);
    return jobs.map(jobStr => JSON.parse(jobStr));
  }

  async reprocessDeadLetterJob(jobId: string): Promise<boolean> {
    const jobs = await this.getDeadLetterJobs();
    const job = jobs.find(j => j.id === jobId);
    
    if (!job) return false;

    // Reset attempts and re-add to queue
    job.attempts = 0;
    await this.addJob(job);

    // Remove from dead letter queue
    const deadLetterJobs = await this.redis.lrange(this.DEAD_LETTER_KEY, 0, -1);
    for (let i = 0; i < deadLetterJobs.length; i++) {
      const dlJob = JSON.parse(deadLetterJobs[i]);
      if (dlJob.id === jobId) {
        await this.redis.lrem(this.DEAD_LETTER_KEY, 1, deadLetterJobs[i]);
        break;
      }
    }

    return true;
  }

  async clearDeadLetterQueue(): Promise<number> {
    const count = await this.redis.llen(this.DEAD_LETTER_KEY);
    await this.redis.del(this.DEAD_LETTER_KEY);
    return count;
  }
}