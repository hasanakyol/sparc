export interface Logger {
  info: (message: string, meta?: any) => void;
  warn: (message: string, meta?: any) => void;
  error: (message: string, meta?: any) => void;
  debug: (message: string, meta?: any) => void;
}

export class ConsoleLogger implements Logger {
  private serviceName: string;

  constructor(serviceName: string) {
    this.serviceName = serviceName;
  }

  private log(level: string, message: string, meta?: any): void {
    console.log(JSON.stringify({
      level,
      service: this.serviceName,
      message,
      ...meta,
      timestamp: new Date().toISOString()
    }));
  }

  info(message: string, meta?: any): void {
    this.log('info', message, meta);
  }

  warn(message: string, meta?: any): void {
    this.log('warn', message, meta);
  }

  error(message: string, meta?: any): void {
    this.log('error', message, meta);
  }

  debug(message: string, meta?: any): void {
    if (process.env.NODE_ENV !== 'production') {
      this.log('debug', message, meta);
    }
  }
}