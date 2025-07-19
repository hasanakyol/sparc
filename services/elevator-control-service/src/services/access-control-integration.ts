import { Logger } from '../utils/logger';

export class AccessControlIntegration {
  constructor(
    private serviceUrl: string,
    private logger: Logger
  ) {}

  async checkUserAccess(userId: string, buildingId: string, targetFloor: number): Promise<boolean> {
    try {
      const response = await fetch(`${this.serviceUrl}/api/access/check`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          userId,
          resourceType: 'FLOOR',
          resourceId: `${buildingId}:${targetFloor}`,
          action: 'ACCESS',
        }),
        signal: AbortSignal.timeout(3000)
      });

      if (!response.ok) {
        this.logger.error('Access control check failed', { 
          userId, 
          buildingId, 
          targetFloor, 
          status: response.status 
        });
        return false;
      }

      const data = await response.json();
      return data.allowed;
    } catch (error) {
      this.logger.error('Access control check failed', { 
        userId, 
        buildingId, 
        targetFloor, 
        error: error.message 
      });
      return false;
    }
  }

  async getUserSchedule(userId: string): Promise<any> {
    try {
      const response = await fetch(`${this.serviceUrl}/api/users/${userId}/schedule`, {
        signal: AbortSignal.timeout(3000)
      });

      if (!response.ok) {
        this.logger.error('User schedule retrieval failed', { 
          userId, 
          status: response.status 
        });
        return null;
      }

      return await response.json();
    } catch (error) {
      this.logger.error('User schedule retrieval failed', { 
        userId, 
        error: error.message 
      });
      return null;
    }
  }

  async getAccessRules(buildingId: string): Promise<any> {
    try {
      const response = await fetch(`${this.serviceUrl}/api/buildings/${buildingId}/access-rules`, {
        signal: AbortSignal.timeout(5000)
      });

      if (!response.ok) {
        this.logger.error('Access rules retrieval failed', { 
          buildingId, 
          status: response.status 
        });
        return null;
      }

      return await response.json();
    } catch (error) {
      this.logger.error('Access rules retrieval failed', { 
        buildingId, 
        error: error.message 
      });
      return null;
    }
  }
}