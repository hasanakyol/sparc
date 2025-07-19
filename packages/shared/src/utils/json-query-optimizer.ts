import { Prisma } from '@prisma/client';

/**
 * Optimized JSON query utilities for PostgreSQL JSONB columns
 * These utilities provide type-safe and performant queries for JSON data
 */

export interface JsonQueryOptions {
  path: string[];
  operator?: 'equals' | 'contains' | 'exists' | 'gt' | 'gte' | 'lt' | 'lte' | 'in' | 'not';
  value?: any;
  caseSensitive?: boolean;
}

/**
 * Build an optimized JSONB query for Prisma
 */
export function buildJsonQuery(field: string, options: JsonQueryOptions): Prisma.Sql {
  const { path, operator = 'equals', value, caseSensitive = true } = options;
  const pathStr = path.map(p => `'${p}'`).join(',');
  const jsonPath = `${field}->{${pathStr}}`;

  switch (operator) {
    case 'equals':
      if (typeof value === 'string' && !caseSensitive) {
        return Prisma.sql`LOWER(${Prisma.raw(jsonPath)}::text) = LOWER(${value}::text)`;
      }
      return Prisma.sql`${Prisma.raw(jsonPath)} = ${JSON.stringify(value)}::jsonb`;

    case 'contains':
      if (typeof value === 'string') {
        return Prisma.sql`${Prisma.raw(jsonPath)}::text LIKE ${'%' + value + '%'}`;
      }
      return Prisma.sql`${Prisma.raw(jsonPath)} @> ${JSON.stringify(value)}::jsonb`;

    case 'exists':
      return Prisma.sql`${Prisma.raw(jsonPath)} IS NOT NULL`;

    case 'gt':
      return Prisma.sql`(${Prisma.raw(jsonPath)})::numeric > ${value}`;

    case 'gte':
      return Prisma.sql`(${Prisma.raw(jsonPath)})::numeric >= ${value}`;

    case 'lt':
      return Prisma.sql`(${Prisma.raw(jsonPath)})::numeric < ${value}`;

    case 'lte':
      return Prisma.sql`(${Prisma.raw(jsonPath)})::numeric <= ${value}`;

    case 'in':
      if (!Array.isArray(value)) {
        throw new Error('Value must be an array for "in" operator');
      }
      const values = value.map(v => JSON.stringify(v)).join(',');
      return Prisma.sql`${Prisma.raw(jsonPath)} IN (${Prisma.raw(values)})`;

    case 'not':
      return Prisma.sql`${Prisma.raw(jsonPath)} != ${JSON.stringify(value)}::jsonb`;

    default:
      throw new Error(`Unknown operator: ${operator}`);
  }
}

/**
 * Build a complex JSON query with multiple conditions
 */
export function buildComplexJsonQuery(
  field: string,
  conditions: JsonQueryOptions[],
  logic: 'AND' | 'OR' = 'AND'
): Prisma.Sql {
  const queries = conditions.map(cond => buildJsonQuery(field, cond));
  
  if (logic === 'AND') {
    return Prisma.join(queries, ' AND ');
  } else {
    return Prisma.join(queries, ' OR ');
  }
}

/**
 * Extract and aggregate JSON values efficiently
 */
export function jsonAggregateQuery(
  tableName: string,
  jsonField: string,
  path: string[],
  aggregateType: 'count' | 'sum' | 'avg' | 'min' | 'max' | 'array_agg',
  whereClause?: Prisma.Sql
): Prisma.Sql {
  const pathStr = path.map(p => `'${p}'`).join(',');
  const jsonPath = `${jsonField}->{${pathStr}}`;
  
  let aggregateSql: string;
  switch (aggregateType) {
    case 'count':
      aggregateSql = `COUNT(${jsonPath})`;
      break;
    case 'sum':
      aggregateSql = `SUM((${jsonPath})::numeric)`;
      break;
    case 'avg':
      aggregateSql = `AVG((${jsonPath})::numeric)`;
      break;
    case 'min':
      aggregateSql = `MIN((${jsonPath})::numeric)`;
      break;
    case 'max':
      aggregateSql = `MAX((${jsonPath})::numeric)`;
      break;
    case 'array_agg':
      aggregateSql = `ARRAY_AGG(${jsonPath})`;
      break;
  }

  if (whereClause) {
    return Prisma.sql`
      SELECT ${Prisma.raw(aggregateSql)} as result
      FROM ${Prisma.raw(tableName)}
      WHERE ${whereClause}
    `;
  }

  return Prisma.sql`
    SELECT ${Prisma.raw(aggregateSql)} as result
    FROM ${Prisma.raw(tableName)}
  `;
}

/**
 * Create a GIN index query for JSON columns
 */
export function createJsonIndexQuery(
  tableName: string,
  columnName: string,
  indexName: string,
  path?: string[]
): string {
  if (path && path.length > 0) {
    const pathStr = path.map(p => `'${p}'`).join(',');
    return `CREATE INDEX CONCURRENTLY IF NOT EXISTS ${indexName} ON ${tableName} USING gin((${columnName}->{${pathStr}}))`;
  }
  return `CREATE INDEX CONCURRENTLY IF NOT EXISTS ${indexName} ON ${tableName} USING gin(${columnName})`;
}

/**
 * Query builder for common JSON patterns
 */
export class JsonQueryBuilder {
  private conditions: Array<{ field: string; options: JsonQueryOptions }> = [];
  private orderBy: Array<{ field: string; path: string[]; direction: 'asc' | 'desc' }> = [];

  where(field: string, options: JsonQueryOptions): this {
    this.conditions.push({ field, options });
    return this;
  }

  orderByJson(field: string, path: string[], direction: 'asc' | 'desc' = 'asc'): this {
    this.orderBy.push({ field, path, direction });
    return this;
  }

  build(): {
    where: Prisma.Sql | undefined;
    orderBy: Prisma.Sql | undefined;
  } {
    let whereClause: Prisma.Sql | undefined;
    if (this.conditions.length > 0) {
      const queries = this.conditions.map(cond => 
        buildJsonQuery(cond.field, cond.options)
      );
      whereClause = Prisma.join(queries, ' AND ');
    }

    let orderByClause: Prisma.Sql | undefined;
    if (this.orderBy.length > 0) {
      const orderQueries = this.orderBy.map(ob => {
        const pathStr = ob.path.map(p => `'${p}'`).join(',');
        return Prisma.raw(`${ob.field}->{${pathStr}} ${ob.direction.toUpperCase()}`);
      });
      orderByClause = Prisma.join(orderQueries, ', ');
    }

    return { where: whereClause, orderBy: orderByClause };
  }
}

/**
 * Optimized queries for common JSON patterns in SPARC
 */
export const SparcJsonQueries = {
  /**
   * Query user by role
   */
  userByRole(role: string): Prisma.Sql {
    return Prisma.sql`roles @> ${JSON.stringify([role])}::jsonb`;
  },

  /**
   * Query user by permission
   */
  userByPermission(resource: string, action: string): Prisma.Sql {
    return buildJsonQuery('permissions', {
      path: [resource],
      operator: 'contains',
      value: action
    });
  },

  /**
   * Query alerts by detail type
   */
  alertByDetailType(type: string): Prisma.Sql {
    return buildJsonQuery('details', {
      path: ['type'],
      operator: 'equals',
      value: type
    });
  },

  /**
   * Query organizations by setting
   */
  organizationBySetting(key: string, value: any): Prisma.Sql {
    return buildJsonQuery('settings', {
      path: [key],
      operator: 'equals',
      value
    });
  },

  /**
   * Query devices by capability
   */
  deviceByCapability(capability: string, enabled: boolean = true): Prisma.Sql {
    return buildJsonQuery('capabilities', {
      path: [capability],
      operator: 'equals',
      value: enabled
    });
  },

  /**
   * Query zones by access rule
   */
  zoneByAccessRule(ruleType: string, value: any): Prisma.Sql {
    return buildJsonQuery('access_rules', {
      path: [ruleType],
      operator: 'equals',
      value
    });
  }
};

/**
 * Performance tips for JSON queries:
 * 
 * 1. Use GIN indexes for frequently queried JSON paths
 * 2. Avoid deep nesting (>3 levels) in JSON structures
 * 3. Extract frequently queried values to separate columns
 * 4. Use jsonb_path_ops for faster @> operations
 * 5. Consider materialized views for complex aggregations
 * 
 * Example index creation:
 * CREATE INDEX idx_users_roles ON users USING gin(roles);
 * CREATE INDEX idx_alerts_details_type ON alerts USING gin((details->'type'));
 */