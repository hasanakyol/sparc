import jsonpath from 'jsonpath';
import { logger } from '@sparc/shared';
import { DataMapping } from '../types';
import { validate } from 'jsonschema';

export class TransformationService {
  
  async transformData(
    source: any,
    mappings: DataMapping[]
  ): Promise<any> {
    const result: any = {};

    for (const mapping of mappings) {
      try {
        const value = await this.extractValue(source, mapping);
        this.setNestedValue(result, mapping.target, value);
      } catch (error) {
        logger.error('Transformation failed', { mapping, error });
        if (mapping.defaultValue !== undefined) {
          this.setNestedValue(result, mapping.target, mapping.defaultValue);
        }
      }
    }

    return result;
  }

  async transformRequest(
    request: any,
    config: any
  ): Promise<any> {
    const transformed = { ...request };

    // Apply header transformations
    if (config.headers) {
      transformed.headers = {
        ...request.headers,
        ...config.headers
      };
    }

    // Apply query parameter transformations
    if (config.queryParams && request.path) {
      const params = new URLSearchParams();
      Object.entries(config.queryParams).forEach(([key, value]) => {
        params.append(key, String(value));
      });
      const separator = request.path.includes('?') ? '&' : '?';
      transformed.path = `${request.path}${separator}${params.toString()}`;
    }

    // Apply body transformations
    if (config.bodyMapping && request.body) {
      const bodyData = typeof request.body === 'string' 
        ? JSON.parse(request.body) 
        : request.body;
      
      transformed.body = await this.transformData(bodyData, config.bodyMapping);
      
      if (typeof request.body === 'string') {
        transformed.body = JSON.stringify(transformed.body);
      }
    }

    return transformed;
  }

  async transformResponse(
    response: any,
    config: any
  ): Promise<any> {
    const transformed = { ...response };

    // Apply header transformations
    if (config.headers) {
      transformed.headers = new Headers(response.headers);
      Object.entries(config.headers).forEach(([key, value]) => {
        transformed.headers.set(key, String(value));
      });
    }

    // Apply body transformations
    if (config.bodyMapping && response.body) {
      const bodyData = typeof response.body === 'string' 
        ? JSON.parse(response.body) 
        : response.body;
      
      transformed.body = await this.transformData(bodyData, config.bodyMapping);
      
      if (typeof response.body === 'string') {
        transformed.body = JSON.stringify(transformed.body);
      }
    }

    return transformed;
  }

  async validateSchema(data: any, schema: any): Promise<boolean> {
    const result = validate(data, schema);
    return result.valid;
  }

  async applyTemplate(template: string, context: any): Promise<string> {
    // Simple template engine - replace {{path}} with values
    let result = template;
    
    const replaceTokens = (str: string, data: any, prefix = ''): string => {
      Object.entries(data).forEach(([key, value]) => {
        const token = prefix ? `${prefix}.${key}` : key;
        if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
          str = replaceTokens(str, value, token);
        } else {
          const regex = new RegExp(`{{\\s*${token}\\s*}}`, 'g');
          str = str.replace(regex, String(value));
        }
      });
      return str;
    };

    result = replaceTokens(result, context);
    
    // Handle array notation {{items[0].name}}
    const arrayRegex = /{{([^}]+)\[(\d+)\]\.?([^}]*)}}/g;
    result = result.replace(arrayRegex, (match, path, index, property) => {
      try {
        const value = jsonpath.query(context, `$.${path}`)[0];
        if (Array.isArray(value) && value[index]) {
          if (property) {
            return this.getNestedValue(value[index], property);
          }
          return String(value[index]);
        }
        return match;
      } catch {
        return match;
      }
    });

    return result;
  }

  // Private helper methods

  private async extractValue(source: any, mapping: DataMapping): Promise<any> {
    let value: any;

    switch (mapping.transform) {
      case 'direct':
        value = this.getNestedValue(source, mapping.source);
        break;
      
      case 'jsonpath':
        const results = jsonpath.query(source, mapping.source);
        value = results.length > 0 ? results[0] : undefined;
        break;
      
      case 'template':
        if (mapping.template) {
          value = await this.applyTemplate(mapping.template, source);
        }
        break;
      
      case 'javascript':
        if (mapping.script) {
          value = await this.executeScript(mapping.script, source);
        }
        break;
      
      default:
        value = this.getNestedValue(source, mapping.source);
    }

    if (value === undefined && mapping.defaultValue !== undefined) {
      value = mapping.defaultValue;
    }

    return value;
  }

  private getNestedValue(obj: any, path: string): any {
    return path.split('.').reduce((acc, part) => {
      if (acc === null || acc === undefined) return undefined;
      
      // Handle array notation
      const arrayMatch = part.match(/^(\w+)\[(\d+)\]$/);
      if (arrayMatch) {
        const [, key, index] = arrayMatch;
        return acc[key]?.[parseInt(index, 10)];
      }
      
      return acc[part];
    }, obj);
  }

  private setNestedValue(obj: any, path: string, value: any): void {
    const parts = path.split('.');
    const last = parts.pop()!;
    
    const target = parts.reduce((acc, part) => {
      if (!acc[part]) {
        acc[part] = {};
      }
      return acc[part];
    }, obj);
    
    target[last] = value;
  }

  private async executeScript(script: string, context: any): Promise<any> {
    // In production, this should use a sandboxed environment like VM2
    // For now, we'll use a limited evaluation
    try {
      // Create a limited context
      const limitedContext = {
        data: context,
        Math,
        Date,
        JSON,
        parseInt,
        parseFloat,
        String,
        Number,
        Boolean,
        Array
      };

      // Use Function constructor with limited scope
      const fn = new Function(...Object.keys(limitedContext), script);
      return fn(...Object.values(limitedContext));
    } catch (error) {
      logger.error('Script execution failed', { script, error });
      throw new Error('Script execution failed');
    }
  }
}