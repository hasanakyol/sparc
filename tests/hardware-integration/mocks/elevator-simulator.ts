// Mock elevator hardware simulators for testing
export const mockElevatorSimulator = {
  startKONE: async () => {
    return {
      protocol: 'KONE',
      port: 5001,
      status: 'running',
      elevators: [
        { id: 'A1', floors: 20, currentFloor: 1 },
        { id: 'A2', floors: 20, currentFloor: 10 }
      ],
      simulateFailure: async () => {
        // Simulate connection failure
      },
      simulatePowerFailure: async () => {
        // Simulate power failure
      },
      stop: async () => {
        // Stop simulator
      }
    };
  },

  startSchindler: async () => {
    return {
      protocol: 'Schindler',
      port: 5002,
      status: 'running',
      technology: 'PORT',
      elevators: [
        { id: 'B1', floors: 30, currentFloor: 15 },
        { id: 'B2', floors: 30, currentFloor: 1 }
      ],
      simulateFailure: async () => {},
      simulatePowerFailure: async () => {},
      stop: async () => {}
    };
  },

  startThyssenKrupp: async () => {
    return {
      protocol: 'ThyssenKrupp',
      port: 5003,
      status: 'running',
      system: 'TWIN',
      shafts: [
        { id: 'A', cars: ['A1', 'A2'], floors: 40 }
      ],
      simulateFailure: async () => {},
      simulatePowerFailure: async () => {},
      stop: async () => {}
    };
  },

  startMitsubishi: async () => {
    return {
      protocol: 'Mitsubishi',
      port: 5004,
      status: 'running',
      system: 'MELDAS',
      groups: [
        { id: 'MAIN', elevators: ['D1', 'D2', 'D3'], floors: 25 }
      ],
      simulateFailure: async () => {},
      simulatePowerFailure: async () => {},
      stop: async () => {}
    };
  }
};