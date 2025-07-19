import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { Logger } from '../utils/logger';
import { DestinationDispatchAssignment } from '../types';

interface DispatchRequest {
  userId: string;
  targetFloor: number;
  priority: 'LOW' | 'NORMAL' | 'HIGH' | 'EMERGENCY';
}

export class DestinationDispatchService {
  private pendingRequests = new Map<string, DispatchRequest[]>();

  constructor(
    private prisma: PrismaClient,
    private redis: Redis,
    private logger: Logger
  ) {}

  async optimizeElevatorAssignment(
    buildingId: string, 
    requests: DispatchRequest[]
  ): Promise<DestinationDispatchAssignment[]> {
    // Get all elevators in the building
    const elevators = await this.prisma.elevatorControl.findMany({
      where: { buildingId },
    });

    if (elevators.length === 0) {
      this.logger.error('No elevators found in building', { buildingId });
      return [];
    }

    const assignments: DestinationDispatchAssignment[] = [];
    
    // Group requests by floor for optimization
    const requestsByFloor = new Map<number, DispatchRequest[]>();
    for (const request of requests) {
      const floorRequests = requestsByFloor.get(request.targetFloor) || [];
      floorRequests.push(request);
      requestsByFloor.set(request.targetFloor, floorRequests);
    }

    // Assign elevators based on current status and optimization algorithm
    for (const [floor, floorRequests] of requestsByFloor) {
      const bestElevator = await this.findBestElevator(elevators, floor, floorRequests.length);
      
      if (bestElevator) {
        for (const request of floorRequests) {
          assignments.push({
            elevatorId: bestElevator.id,
            elevatorName: bestElevator.name,
            userId: request.userId,
            targetFloor: request.targetFloor,
            priority: request.priority,
            estimatedArrival: this.calculateEstimatedArrival(bestElevator, request.targetFloor),
          });
        }
      }
    }

    return assignments;
  }

  private async findBestElevator(elevators: any[], targetFloor: number, passengerCount: number): Promise<any> {
    let bestElevator = null;
    let bestScore = Infinity;

    for (const elevator of elevators) {
      // Check if elevator serves this floor
      const floorsServed = elevator.floorsServed as number[];
      if (!floorsServed.includes(targetFloor)) {
        continue;
      }

      // Get current status from cache
      const status = await this.getElevatorStatus(elevator.id);
      if (!status || status.operationalStatus !== 'NORMAL') {
        continue;
      }

      // Calculate score based on multiple factors
      const score = this.calculateElevatorScore(elevator, status, targetFloor, passengerCount);
      
      if (score < bestScore) {
        bestScore = score;
        bestElevator = elevator;
      }
    }

    return bestElevator;
  }

  private calculateElevatorScore(
    elevator: any, 
    status: any, 
    targetFloor: number, 
    passengerCount: number
  ): number {
    let score = 0;

    // Distance factor (most important)
    const distance = Math.abs(status.currentFloor - targetFloor);
    score += distance * 10;

    // Direction factor
    const goingUp = targetFloor > status.currentFloor;
    if (status.direction === 'STATIONARY') {
      // Elevator is idle, good candidate
      score += 0;
    } else if ((goingUp && status.direction === 'UP') || (!goingUp && status.direction === 'DOWN')) {
      // Elevator is going in the right direction
      score += 5;
    } else {
      // Elevator is going in opposite direction
      score += 20;
    }

    // Load factor
    const loadPenalty = (status.load / 100) * 15;
    score += loadPenalty;

    // Capacity check
    const estimatedLoad = status.load + (passengerCount * 10); // Assume each passenger adds 10% load
    if (estimatedLoad > 80) {
      score += 50; // Heavy penalty for potentially overloaded elevator
    }

    return score;
  }

  private calculateEstimatedArrival(elevator: any, targetFloor: number): Date {
    // Simple calculation: assume 3 seconds per floor + 5 seconds for stops
    const currentFloor = elevator.currentFloor || 1;
    const travelTime = Math.abs(currentFloor - targetFloor) * 3;
    const stopTime = 5;
    const totalTime = travelTime + stopTime;
    
    return new Date(Date.now() + totalTime * 1000);
  }

  private async getElevatorStatus(elevatorId: string): Promise<any> {
    const cached = await this.redis.get(`elevator:status:${elevatorId}`);
    if (cached) {
      return JSON.parse(cached);
    }
    return null;
  }

  async addPendingRequest(buildingId: string, request: DispatchRequest): void {
    const requests = this.pendingRequests.get(buildingId) || [];
    requests.push(request);
    this.pendingRequests.set(buildingId, requests);

    // Process batch after delay to allow grouping
    setTimeout(() => this.processPendingRequests(buildingId), 1000);
  }

  private async processPendingRequests(buildingId: string): Promise<void> {
    const requests = this.pendingRequests.get(buildingId);
    if (!requests || requests.length === 0) {
      return;
    }

    this.pendingRequests.delete(buildingId);

    try {
      const assignments = await this.optimizeElevatorAssignment(buildingId, requests);
      
      // Execute assignments
      for (const assignment of assignments) {
        this.logger.info('Dispatching elevator', assignment);
        // In a real implementation, this would call the elevator service
      }
    } catch (error) {
      this.logger.error('Failed to process pending requests', { 
        buildingId, 
        error: error.message 
      });
    }
  }
}