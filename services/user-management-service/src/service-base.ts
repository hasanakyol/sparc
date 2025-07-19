import { MicroserviceBase, ServiceConfig } from '@sparc/shared/patterns/service-base';
import { db, sqlConnection } from './db';

export abstract class ExtendedMicroserviceBase extends MicroserviceBase {
  protected db = db;

  protected async cleanup(): Promise<void> {
    // Close Drizzle/Postgres connection
    await sqlConnection.end();
    
    // Call parent cleanup
    await super.cleanup();
  }
}