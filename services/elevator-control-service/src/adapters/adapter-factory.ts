import { BaseElevatorAdapter, ElevatorConfig } from './base.adapter';
import { OtisAdapter } from './otis.adapter';
import { KoneAdapter } from './kone.adapter';
import { SchindlerAdapter } from './schindler.adapter';
import { ThyssenKruppAdapter } from './thyssenkrupp.adapter';
import { MitsubishiAdapter } from './mitsubishi.adapter';
import { Logger } from '../utils/logger';
import { ManufacturerType } from '../types';

export class AdapterFactory {
  static create(manufacturer: ManufacturerType, config: ElevatorConfig, logger: Logger): BaseElevatorAdapter {
    switch (manufacturer) {
      case 'OTIS':
        return new OtisAdapter(config, logger);
      
      case 'KONE':
        return new KoneAdapter(config, logger);
      
      case 'SCHINDLER':
        return new SchindlerAdapter(config, logger);
      
      case 'THYSSENKRUPP':
        return new ThyssenKruppAdapter(config, logger);
      
      case 'MITSUBISHI':
        return new MitsubishiAdapter(config, logger);
      
      case 'FUJITEC':
        // TODO: Implement Fujitec adapter
        logger.warn('Fujitec adapter not implemented, using OTIS adapter as fallback');
        return new OtisAdapter(config, logger);
      
      case 'GENERIC':
      default:
        logger.info('Using OTIS adapter for generic/unknown manufacturer');
        return new OtisAdapter(config, logger);
    }
  }

  static getAdapterConfig(manufacturer: ManufacturerType, baseConfig: Partial<ElevatorConfig>): ElevatorConfig {
    const defaultConfig: ElevatorConfig = {
      baseUrl: '',
      apiKey: '',
      timeout: 5000,
      retryAttempts: 3,
      retryDelay: 1000,
      connectionPoolSize: 5,
      simulatorMode: process.env.ELEVATOR_SIMULATOR_MODE === 'true',
      simulatorOptions: {
        responseDelay: 100,
        failureRate: 0.05,
        randomizeStatus: true,
        floors: 20,
        travelTimePerFloor: 3000
      }
    };

    // Manufacturer-specific configuration
    switch (manufacturer) {
      case 'OTIS':
        return {
          ...defaultConfig,
          ...baseConfig,
          baseUrl: process.env.OTIS_API_URL || baseConfig.baseUrl || '',
          apiKey: process.env.OTIS_API_KEY || baseConfig.apiKey || ''
        };
      
      case 'KONE':
        return {
          ...defaultConfig,
          ...baseConfig,
          baseUrl: process.env.KONE_API_URL || baseConfig.baseUrl || '',
          apiKey: process.env.KONE_API_KEY || baseConfig.apiKey || ''
        };
      
      case 'SCHINDLER':
        return {
          ...defaultConfig,
          ...baseConfig,
          baseUrl: process.env.SCHINDLER_API_URL || baseConfig.baseUrl || '',
          apiKey: process.env.SCHINDLER_API_KEY || baseConfig.apiKey || ''
        };
      
      case 'THYSSENKRUPP':
        return {
          ...defaultConfig,
          ...baseConfig,
          baseUrl: process.env.THYSSENKRUPP_API_URL || baseConfig.baseUrl || '',
          apiKey: process.env.THYSSENKRUPP_API_KEY || baseConfig.apiKey || ''
        };
      
      case 'MITSUBISHI':
        return {
          ...defaultConfig,
          ...baseConfig,
          baseUrl: process.env.MITSUBISHI_API_URL || baseConfig.baseUrl || '',
          apiKey: process.env.MITSUBISHI_API_KEY || baseConfig.apiKey || ''
        };
      
      case 'FUJITEC':
        return {
          ...defaultConfig,
          ...baseConfig,
          baseUrl: process.env.FUJITEC_API_URL || baseConfig.baseUrl || '',
          apiKey: process.env.FUJITEC_API_KEY || baseConfig.apiKey || ''
        };
      
      default:
        return {
          ...defaultConfig,
          ...baseConfig
        };
    }
  }
}