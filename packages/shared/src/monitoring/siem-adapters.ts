import { SecurityEvent } from '../security/siem';
import { SIEMProvider } from './types';
import { logger } from '../utils/logger';

export abstract class SIEMAdapter {
  protected provider: SIEMProvider;

  constructor(provider: SIEMProvider) {
    this.provider = provider;
  }

  abstract async sendEvent(event: SecurityEvent): Promise<void>;
  abstract async sendBatch(events: SecurityEvent[]): Promise<void>;
  abstract async testConnection(): Promise<boolean>;
  abstract async queryEvents(query: any): Promise<SecurityEvent[]>;
}

export class SplunkAdapter extends SIEMAdapter {
  private splunkUrl: string;
  private token: string;

  constructor(provider: SIEMProvider) {
    super(provider);
    this.splunkUrl = provider.config.url;
    this.token = provider.config.token;
  }

  async sendEvent(event: SecurityEvent): Promise<void> {
    try {
      const splunkEvent = {
        time: event.timestamp.getTime() / 1000,
        host: event.source,
        source: 'sparc',
        sourcetype: 'security',
        event: {
          event_type: event.eventType,
          severity: event.severity,
          user_id: event.userId,
          organization_id: event.organizationId,
          ip_address: event.ipAddress,
          user_agent: event.userAgent,
          details: event.details,
          metadata: event.metadata
        }
      };

      const response = await fetch(`${this.splunkUrl}/services/collector/event`, {
        method: 'POST',
        headers: {
          'Authorization': `Splunk ${this.token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(splunkEvent)
      });

      if (!response.ok) {
        throw new Error(`Splunk API error: ${response.statusText}`);
      }
    } catch (error) {
      logger.error('Failed to send event to Splunk', { error, event });
      throw error;
    }
  }

  async sendBatch(events: SecurityEvent[]): Promise<void> {
    const batchPayload = events.map(event => ({
      time: event.timestamp.getTime() / 1000,
      host: event.source,
      source: 'sparc',
      sourcetype: 'security',
      event: {
        event_type: event.eventType,
        severity: event.severity,
        user_id: event.userId,
        organization_id: event.organizationId,
        ip_address: event.ipAddress,
        user_agent: event.userAgent,
        details: event.details,
        metadata: event.metadata
      }
    }));

    const response = await fetch(`${this.splunkUrl}/services/collector/event`, {
      method: 'POST',
      headers: {
        'Authorization': `Splunk ${this.token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(batchPayload)
    });

    if (!response.ok) {
      throw new Error(`Splunk batch API error: ${response.statusText}`);
    }
  }

  async testConnection(): Promise<boolean> {
    try {
      const response = await fetch(`${this.splunkUrl}/services/collector/health`, {
        headers: {
          'Authorization': `Splunk ${this.token}`
        }
      });
      return response.ok;
    } catch (error) {
      logger.error('Splunk connection test failed', { error });
      return false;
    }
  }

  async queryEvents(query: any): Promise<SecurityEvent[]> {
    const searchQuery = `search index=${this.provider.config.index || 'main'} source=sparc ${query.filter || ''}`;
    
    const response = await fetch(`${this.splunkUrl}/services/search/jobs`, {
      method: 'POST',
      headers: {
        'Authorization': `Splunk ${this.token}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        search: searchQuery,
        output_mode: 'json',
        earliest_time: query.startTime || '-24h',
        latest_time: query.endTime || 'now'
      })
    });

    if (!response.ok) {
      throw new Error('Splunk search failed');
    }

    const result = await response.json();
    return this.mapSplunkResults(result.results || []);
  }

  private mapSplunkResults(results: any[]): SecurityEvent[] {
    return results.map(result => ({
      id: result._raw?.event?.id || crypto.randomUUID(),
      timestamp: new Date(result._time),
      eventType: result._raw?.event?.event_type,
      severity: result._raw?.event?.severity,
      source: result.host,
      userId: result._raw?.event?.user_id,
      organizationId: result._raw?.event?.organization_id,
      ipAddress: result._raw?.event?.ip_address,
      userAgent: result._raw?.event?.user_agent,
      details: result._raw?.event?.details || {},
      metadata: result._raw?.event?.metadata || {}
    }));
  }
}

export class ElasticSearchAdapter extends SIEMAdapter {
  private elasticUrl: string;
  private apiKey: string;
  private index: string;

  constructor(provider: SIEMProvider) {
    super(provider);
    this.elasticUrl = provider.config.url;
    this.apiKey = provider.config.apiKey;
    this.index = provider.config.index || 'sparc-security';
  }

  async sendEvent(event: SecurityEvent): Promise<void> {
    const document = {
      '@timestamp': event.timestamp,
      event_type: event.eventType,
      severity: event.severity,
      source: event.source,
      user: {
        id: event.userId,
        ip: event.ipAddress,
        user_agent: event.userAgent
      },
      organization: {
        id: event.organizationId
      },
      details: event.details,
      metadata: event.metadata,
      tags: ['sparc', 'security']
    };

    const response = await fetch(`${this.elasticUrl}/${this.index}/_doc/${event.id}`, {
      method: 'PUT',
      headers: {
        'Authorization': `ApiKey ${this.apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(document)
    });

    if (!response.ok) {
      throw new Error(`ElasticSearch API error: ${response.statusText}`);
    }
  }

  async sendBatch(events: SecurityEvent[]): Promise<void> {
    const bulkBody = events.flatMap(event => [
      { index: { _index: this.index, _id: event.id } },
      {
        '@timestamp': event.timestamp,
        event_type: event.eventType,
        severity: event.severity,
        source: event.source,
        user: {
          id: event.userId,
          ip: event.ipAddress,
          user_agent: event.userAgent
        },
        organization: {
          id: event.organizationId
        },
        details: event.details,
        metadata: event.metadata,
        tags: ['sparc', 'security']
      }
    ]);

    const response = await fetch(`${this.elasticUrl}/_bulk`, {
      method: 'POST',
      headers: {
        'Authorization': `ApiKey ${this.apiKey}`,
        'Content-Type': 'application/x-ndjson'
      },
      body: bulkBody.map(item => JSON.stringify(item)).join('\n') + '\n'
    });

    if (!response.ok) {
      throw new Error(`ElasticSearch bulk API error: ${response.statusText}`);
    }
  }

  async testConnection(): Promise<boolean> {
    try {
      const response = await fetch(`${this.elasticUrl}/_cluster/health`, {
        headers: {
          'Authorization': `ApiKey ${this.apiKey}`
        }
      });
      return response.ok;
    } catch (error) {
      logger.error('ElasticSearch connection test failed', { error });
      return false;
    }
  }

  async queryEvents(query: any): Promise<SecurityEvent[]> {
    const searchQuery = {
      query: {
        bool: {
          must: [
            { range: { '@timestamp': { 
              gte: query.startTime || 'now-24h',
              lte: query.endTime || 'now'
            }}},
            ...(query.filters || [])
          ]
        }
      },
      size: query.size || 100,
      sort: [{ '@timestamp': 'desc' }]
    };

    const response = await fetch(`${this.elasticUrl}/${this.index}/_search`, {
      method: 'POST',
      headers: {
        'Authorization': `ApiKey ${this.apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(searchQuery)
    });

    if (!response.ok) {
      throw new Error('ElasticSearch query failed');
    }

    const result = await response.json();
    return this.mapElasticResults(result.hits?.hits || []);
  }

  private mapElasticResults(hits: any[]): SecurityEvent[] {
    return hits.map(hit => ({
      id: hit._id,
      timestamp: new Date(hit._source['@timestamp']),
      eventType: hit._source.event_type,
      severity: hit._source.severity,
      source: hit._source.source,
      userId: hit._source.user?.id,
      organizationId: hit._source.organization?.id,
      ipAddress: hit._source.user?.ip,
      userAgent: hit._source.user?.user_agent,
      details: hit._source.details || {},
      metadata: hit._source.metadata || {}
    }));
  }
}

export class DataDogAdapter extends SIEMAdapter {
  private apiUrl: string;
  private apiKey: string;

  constructor(provider: SIEMProvider) {
    super(provider);
    this.apiUrl = provider.config.apiUrl || 'https://http-intake.logs.datadoghq.com';
    this.apiKey = provider.config.apiKey;
  }

  async sendEvent(event: SecurityEvent): Promise<void> {
    const ddEvent = {
      ddsource: 'sparc',
      ddtags: `env:${process.env.NODE_ENV},service:security-monitoring,severity:${event.severity}`,
      hostname: event.source,
      service: 'sparc-security',
      status: event.severity,
      message: `Security Event: ${event.eventType}`,
      timestamp: event.timestamp.getTime(),
      attributes: {
        event_id: event.id,
        event_type: event.eventType,
        severity: event.severity,
        user_id: event.userId,
        organization_id: event.organizationId,
        ip_address: event.ipAddress,
        user_agent: event.userAgent,
        details: event.details,
        metadata: event.metadata
      }
    };

    const response = await fetch(`${this.apiUrl}/api/v2/logs`, {
      method: 'POST',
      headers: {
        'DD-API-KEY': this.apiKey,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify([ddEvent])
    });

    if (!response.ok) {
      throw new Error(`DataDog API error: ${response.statusText}`);
    }
  }

  async sendBatch(events: SecurityEvent[]): Promise<void> {
    const ddEvents = events.map(event => ({
      ddsource: 'sparc',
      ddtags: `env:${process.env.NODE_ENV},service:security-monitoring,severity:${event.severity}`,
      hostname: event.source,
      service: 'sparc-security',
      status: event.severity,
      message: `Security Event: ${event.eventType}`,
      timestamp: event.timestamp.getTime(),
      attributes: {
        event_id: event.id,
        event_type: event.eventType,
        severity: event.severity,
        user_id: event.userId,
        organization_id: event.organizationId,
        ip_address: event.ipAddress,
        user_agent: event.userAgent,
        details: event.details,
        metadata: event.metadata
      }
    }));

    const response = await fetch(`${this.apiUrl}/api/v2/logs`, {
      method: 'POST',
      headers: {
        'DD-API-KEY': this.apiKey,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(ddEvents)
    });

    if (!response.ok) {
      throw new Error(`DataDog batch API error: ${response.statusText}`);
    }
  }

  async testConnection(): Promise<boolean> {
    try {
      // Send a test log
      const testEvent = {
        ddsource: 'sparc',
        service: 'sparc-security',
        message: 'Connection test',
        timestamp: Date.now()
      };

      const response = await fetch(`${this.apiUrl}/api/v2/logs`, {
        method: 'POST',
        headers: {
          'DD-API-KEY': this.apiKey,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify([testEvent])
      });

      return response.ok;
    } catch (error) {
      logger.error('DataDog connection test failed', { error });
      return false;
    }
  }

  async queryEvents(query: any): Promise<SecurityEvent[]> {
    // DataDog Log Management API for querying
    const ddQuery = {
      query: query.filter || 'service:sparc-security',
      time: {
        from: query.startTime || 'now-24h',
        to: query.endTime || 'now'
      },
      sort: 'timestamp',
      limit: query.size || 100
    };

    const response = await fetch('https://api.datadoghq.com/api/v2/logs/events/search', {
      method: 'POST',
      headers: {
        'DD-API-KEY': this.apiKey,
        'DD-APPLICATION-KEY': this.provider.config.appKey,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(ddQuery)
    });

    if (!response.ok) {
      throw new Error('DataDog query failed');
    }

    const result = await response.json();
    return this.mapDataDogResults(result.data || []);
  }

  private mapDataDogResults(logs: any[]): SecurityEvent[] {
    return logs.map(log => ({
      id: log.attributes?.attributes?.event_id || crypto.randomUUID(),
      timestamp: new Date(log.attributes?.timestamp),
      eventType: log.attributes?.attributes?.event_type,
      severity: log.attributes?.attributes?.severity,
      source: log.attributes?.host,
      userId: log.attributes?.attributes?.user_id,
      organizationId: log.attributes?.attributes?.organization_id,
      ipAddress: log.attributes?.attributes?.ip_address,
      userAgent: log.attributes?.attributes?.user_agent,
      details: log.attributes?.attributes?.details || {},
      metadata: log.attributes?.attributes?.metadata || {}
    }));
  }
}

export class SIEMAdapterFactory {
  static create(provider: SIEMProvider): SIEMAdapter {
    switch (provider.type) {
      case 'splunk':
        return new SplunkAdapter(provider);
      case 'elk':
        return new ElasticSearchAdapter(provider);
      case 'datadog':
        return new DataDogAdapter(provider);
      default:
        throw new Error(`Unsupported SIEM provider: ${provider.type}`);
    }
  }
}