import { Logger } from '../utils/logger';

export interface AlertData {
  alertType: string;
  priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  sourceId: string;
  sourceType: string;
  message: string;
  details?: any;
}

export class AlertServiceIntegration {
  constructor(
    private serviceUrl: string,
    private logger: Logger
  ) {}

  async sendAlert(alertData: AlertData): Promise<void> {
    try {
      const response = await fetch(`${this.serviceUrl}/api/alerts`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(alertData),
        signal: AbortSignal.timeout(3000)
      });

      if (!response.ok) {
        this.logger.error('Alert sending failed', { 
          alertData, 
          status: response.status 
        });
      }
    } catch (error) {
      this.logger.error('Alert sending failed', { 
        alertData, 
        error: error.message 
      });
    }
  }

  async sendElevatorAlert(
    elevatorId: string, 
    alertType: string, 
    message: string, 
    priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'MEDIUM'
  ): Promise<void> {
    await this.sendAlert({
      alertType: `ELEVATOR_${alertType}`,
      priority,
      sourceId: elevatorId,
      sourceType: 'ELEVATOR',
      message,
      details: {
        elevatorId,
        timestamp: new Date().toISOString(),
      },
    });
  }
}