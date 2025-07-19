import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { telemetry } from '@sparc/shared/telemetry';
import {
  SecurityPolicy,
  PolicyRule,
  PolicyCondition,
  PolicyAction,
  PolicyType
} from '../types';
import { SecurityPolicyInput, PolicyUpdateInput } from '../types/schemas';
import { POLICY_TEMPLATES } from '../config/policy-templates';

export class PolicyEngine {
  private policies: Map<string, SecurityPolicy[]> = new Map();
  
  constructor(
    private prisma: PrismaClient,
    private redis: Redis
  ) {}

  async loadPolicies(): Promise<void> {
    return telemetry.withSpan('policyEngine.loadPolicies', async (span) => {
      // Load all active policies into memory for fast evaluation
      const policies = await this.prisma.securityPolicy.findMany({
        where: { enabled: true },
        orderBy: { priority: 'desc' }
      });

      // Group by tenant
      this.policies.clear();
      for (const policy of policies) {
        const tenantPolicies = this.policies.get(policy.tenantId) || [];
        tenantPolicies.push(policy);
        this.policies.set(policy.tenantId, tenantPolicies);
      }

      span.setAttribute('policies.loaded', policies.length);
    });
  }

  async getPolicies(
    tenantId: string,
    filters: { type?: string; enabled?: boolean }
  ): Promise<SecurityPolicy[]> {
    const where: any = { tenantId };
    
    if (filters.type) where.type = filters.type;
    if (filters.enabled !== undefined) where.enabled = filters.enabled;

    return this.prisma.securityPolicy.findMany({
      where,
      orderBy: [
        { priority: 'desc' },
        { createdAt: 'asc' }
      ]
    });
  }

  async createPolicy(
    tenantId: string,
    userId: string,
    policy: SecurityPolicyInput
  ): Promise<SecurityPolicy> {
    return telemetry.withSpan('policyEngine.createPolicy', async (span) => {
      span.setAttributes({
        'tenant.id': tenantId,
        'policy.name': policy.name,
        'policy.type': policy.type
      });

      // Validate policy rules
      this.validatePolicyRules(policy.rules);

      const createdPolicy = await this.prisma.securityPolicy.create({
        data: {
          tenantId,
          ...policy,
          rules: policy.rules as any,
          createdAt: new Date(),
          updatedAt: new Date(),
          version: 1
        }
      });

      // Reload policies for this tenant
      await this.reloadTenantPolicies(tenantId);

      // Log policy creation
      await this.prisma.auditLog.create({
        data: {
          tenantId,
          userId,
          action: 'CREATE',
          resourceType: 'SECURITY_POLICY',
          resourceId: createdPolicy.id,
          details: {
            policyName: policy.name,
            policyType: policy.type
          },
          ipAddress: 'system',
          userAgent: 'policy-engine'
        }
      });

      return createdPolicy;
    });
  }

  async getPolicyById(
    tenantId: string,
    policyId: string
  ): Promise<SecurityPolicy | null> {
    return this.prisma.securityPolicy.findFirst({
      where: {
        id: policyId,
        tenantId
      }
    });
  }

  async updatePolicy(
    tenantId: string,
    policyId: string,
    userId: string,
    updates: Partial<SecurityPolicy>
  ): Promise<SecurityPolicy> {
    return telemetry.withSpan('policyEngine.updatePolicy', async (span) => {
      span.setAttributes({
        'tenant.id': tenantId,
        'policy.id': policyId
      });

      // Get current policy
      const currentPolicy = await this.getPolicyById(tenantId, policyId);
      if (!currentPolicy) {
        throw new Error('Policy not found');
      }

      // Validate rules if being updated
      if (updates.rules) {
        this.validatePolicyRules(updates.rules);
      }

      const updatedPolicy = await this.prisma.securityPolicy.update({
        where: { id: policyId },
        data: {
          ...updates,
          rules: updates.rules as any,
          updatedAt: new Date(),
          version: { increment: 1 }
        }
      });

      // Reload policies
      await this.reloadTenantPolicies(tenantId);

      // Log update
      await this.prisma.auditLog.create({
        data: {
          tenantId,
          userId,
          action: 'UPDATE',
          resourceType: 'SECURITY_POLICY',
          resourceId: policyId,
          details: {
            updates,
            previousVersion: currentPolicy.version
          },
          ipAddress: 'system',
          userAgent: 'policy-engine'
        }
      });

      return updatedPolicy;
    });
  }

  async deletePolicy(
    tenantId: string,
    policyId: string,
    userId: string
  ): Promise<void> {
    return telemetry.withSpan('policyEngine.deletePolicy', async (span) => {
      span.setAttributes({
        'tenant.id': tenantId,
        'policy.id': policyId
      });

      // Soft delete
      await this.prisma.securityPolicy.update({
        where: { id: policyId },
        data: {
          enabled: false,
          deletedAt: new Date()
        }
      });

      // Reload policies
      await this.reloadTenantPolicies(tenantId);

      // Log deletion
      await this.prisma.auditLog.create({
        data: {
          tenantId,
          userId,
          action: 'DELETE',
          resourceType: 'SECURITY_POLICY',
          resourceId: policyId,
          ipAddress: 'system',
          userAgent: 'policy-engine'
        }
      });
    });
  }

  async evaluatePolicies(
    tenantId: string,
    context: any
  ): Promise<{
    action: PolicyAction;
    matchedPolicies: SecurityPolicy[];
    details: any;
  }> {
    return telemetry.withSpan('policyEngine.evaluatePolicies', async (span) => {
      span.setAttributes({
        'tenant.id': tenantId,
        'context.type': context.type
      });

      const tenantPolicies = this.policies.get(tenantId) || [];
      const matchedPolicies: SecurityPolicy[] = [];
      let finalAction: PolicyAction = PolicyAction.ALLOW;
      const details: any = {};

      // Evaluate policies in priority order
      for (const policy of tenantPolicies) {
        if (!policy.enabled) continue;

        const matched = await this.evaluatePolicy(policy, context);
        if (matched) {
          matchedPolicies.push(policy);
          
          // Apply policy action
          const action = this.determinePolicyAction(policy, context);
          
          // DENY takes precedence
          if (action === PolicyAction.DENY) {
            finalAction = PolicyAction.DENY;
            details.deniedBy = policy.name;
            break;
          }
          
          // Accumulate other actions
          if (action === PolicyAction.REQUIRE_MFA && finalAction !== PolicyAction.DENY) {
            finalAction = PolicyAction.REQUIRE_MFA;
            details.requireMFA = true;
          }
          
          if (action === PolicyAction.REQUIRE_APPROVAL) {
            details.requireApproval = true;
          }
          
          if (action === PolicyAction.LOG) {
            details.logRequired = true;
          }
          
          if (action === PolicyAction.ALERT) {
            details.alertRequired = true;
          }
        }
      }

      span.setAttributes({
        'evaluation.action': finalAction,
        'evaluation.matchedCount': matchedPolicies.length
      });

      // Log policy evaluation if required
      if (details.logRequired || finalAction === PolicyAction.DENY) {
        await this.logPolicyEvaluation(tenantId, context, matchedPolicies, finalAction);
      }

      // Send alerts if required
      if (details.alertRequired) {
        await this.sendPolicyAlert(tenantId, context, matchedPolicies);
      }

      return {
        action: finalAction,
        matchedPolicies,
        details
      };
    });
  }

  async testPolicy(
    tenantId: string,
    policyId: string,
    testContext: any
  ): Promise<{
    matched: boolean;
    action: PolicyAction;
    details: any;
  }> {
    const policy = await this.getPolicyById(tenantId, policyId);
    if (!policy) {
      throw new Error('Policy not found');
    }

    const matched = await this.evaluatePolicy(policy, testContext);
    const action = matched ? this.determinePolicyAction(policy, testContext) : PolicyAction.ALLOW;

    return {
      matched,
      action,
      details: {
        policyName: policy.name,
        evaluatedRules: policy.rules.length
      }
    };
  }

  async clonePolicy(
    tenantId: string,
    policyId: string,
    userId: string,
    options: { name: string; description?: string }
  ): Promise<SecurityPolicy> {
    const sourcePolicy = await this.getPolicyById(tenantId, policyId);
    if (!sourcePolicy) {
      throw new Error('Source policy not found');
    }

    const clonedPolicy = await this.createPolicy(tenantId, userId, {
      name: options.name,
      description: options.description || `Cloned from ${sourcePolicy.name}`,
      type: sourcePolicy.type,
      rules: sourcePolicy.rules,
      enabled: false, // Start disabled
      priority: sourcePolicy.priority
    });

    return clonedPolicy;
  }

  async getPolicyViolations(
    tenantId: string,
    filters: { startDate?: string; endDate?: string; policyId?: string }
  ): Promise<any[]> {
    const where: any = {
      tenantId,
      action: 'POLICY_VIOLATION'
    };

    if (filters.startDate || filters.endDate) {
      where.timestamp = {};
      if (filters.startDate) where.timestamp.gte = new Date(filters.startDate);
      if (filters.endDate) where.timestamp.lte = new Date(filters.endDate);
    }

    if (filters.policyId) {
      where.resourceId = filters.policyId;
    }

    const violations = await this.prisma.auditLog.findMany({
      where,
      orderBy: { timestamp: 'desc' }
    });

    return violations.map(v => ({
      id: v.id,
      timestamp: v.timestamp,
      policyId: v.resourceId,
      userId: v.userId,
      details: v.details
    }));
  }

  async exportPolicies(
    tenantId: string,
    format: string
  ): Promise<Buffer> {
    const policies = await this.getPolicies(tenantId, {});

    if (format === 'yaml') {
      // Convert to YAML format
      const yaml = this.convertPoliciesToYAML(policies);
      return Buffer.from(yaml);
    }

    // Default to JSON
    return Buffer.from(JSON.stringify(policies, null, 2));
  }

  async importPolicies(
    tenantId: string,
    userId: string,
    policies: any[],
    overwrite: boolean
  ): Promise<{
    created: number;
    updated: number;
    skipped: number;
  }> {
    let created = 0;
    let updated = 0;
    let skipped = 0;

    for (const policy of policies) {
      // Check if policy exists
      const existing = await this.prisma.securityPolicy.findFirst({
        where: {
          tenantId,
          name: policy.name
        }
      });

      if (existing && !overwrite) {
        skipped++;
        continue;
      }

      if (existing) {
        await this.updatePolicy(tenantId, existing.id, userId, policy);
        updated++;
      } else {
        await this.createPolicy(tenantId, userId, policy);
        created++;
      }
    }

    return { created, updated, skipped };
  }

  async getPolicyTemplates(type?: string): Promise<any[]> {
    if (type && POLICY_TEMPLATES[type]) {
      return POLICY_TEMPLATES[type];
    }

    // Return all templates
    return Object.entries(POLICY_TEMPLATES).reduce((acc, [key, templates]) => {
      return acc.concat(templates.map(t => ({ ...t, category: key })));
    }, [] as any[]);
  }

  private validatePolicyRules(rules: PolicyRule[]): void {
    for (const rule of rules) {
      // Validate condition
      this.validateCondition(rule.condition);
      
      // Validate action
      if (!Object.values(PolicyAction).includes(rule.action)) {
        throw new Error(`Invalid policy action: ${rule.action}`);
      }
    }
  }

  private validateCondition(condition: PolicyCondition): void {
    const validOperators = ['equals', 'not_equals', 'contains', 'greater_than', 'less_than', 'in', 'not_in'];
    
    if (!validOperators.includes(condition.operator)) {
      throw new Error(`Invalid operator: ${condition.operator}`);
    }

    if (!condition.field) {
      throw new Error('Condition field is required');
    }

    // Recursively validate nested conditions
    if (condition.and) {
      for (const subCondition of condition.and) {
        this.validateCondition(subCondition);
      }
    }

    if (condition.or) {
      for (const subCondition of condition.or) {
        this.validateCondition(subCondition);
      }
    }
  }

  private async evaluatePolicy(
    policy: SecurityPolicy,
    context: any
  ): Promise<boolean> {
    for (const rule of policy.rules) {
      const matched = await this.evaluateRule(rule, context);
      if (matched) {
        return true;
      }
    }
    return false;
  }

  private async evaluateRule(
    rule: PolicyRule,
    context: any
  ): Promise<boolean> {
    // Check exceptions first
    if (rule.exceptions) {
      for (const exception of rule.exceptions) {
        if (this.checkException(exception, context)) {
          return false;
        }
      }
    }

    // Evaluate condition
    return this.evaluateCondition(rule.condition, context);
  }

  private evaluateCondition(
    condition: PolicyCondition,
    context: any
  ): boolean {
    const fieldValue = this.getFieldValue(context, condition.field);

    let result = false;
    switch (condition.operator) {
      case 'equals':
        result = fieldValue === condition.value;
        break;
      case 'not_equals':
        result = fieldValue !== condition.value;
        break;
      case 'contains':
        result = String(fieldValue).includes(String(condition.value));
        break;
      case 'greater_than':
        result = Number(fieldValue) > Number(condition.value);
        break;
      case 'less_than':
        result = Number(fieldValue) < Number(condition.value);
        break;
      case 'in':
        result = Array.isArray(condition.value) && condition.value.includes(fieldValue);
        break;
      case 'not_in':
        result = Array.isArray(condition.value) && !condition.value.includes(fieldValue);
        break;
    }

    // Handle AND conditions
    if (condition.and && condition.and.length > 0) {
      result = result && condition.and.every(c => this.evaluateCondition(c, context));
    }

    // Handle OR conditions
    if (condition.or && condition.or.length > 0) {
      result = result || condition.or.some(c => this.evaluateCondition(c, context));
    }

    return result;
  }

  private getFieldValue(context: any, field: string): any {
    // Handle nested fields (e.g., "user.role")
    const parts = field.split('.');
    let value = context;
    
    for (const part of parts) {
      value = value?.[part];
    }
    
    return value;
  }

  private checkException(exception: any, context: any): boolean {
    if (exception.userId && context.userId === exception.userId) {
      return true;
    }
    
    if (exception.roleId && context.roleId === exception.roleId) {
      return true;
    }
    
    if (exception.resourceId && context.resourceId === exception.resourceId) {
      return true;
    }
    
    if (exception.validUntil && new Date() > new Date(exception.validUntil)) {
      return false;
    }
    
    return false;
  }

  private determinePolicyAction(
    policy: SecurityPolicy,
    context: any
  ): PolicyAction {
    // Find the first matching rule and return its action
    for (const rule of policy.rules) {
      if (this.evaluateCondition(rule.condition, context)) {
        return rule.action;
      }
    }
    
    return PolicyAction.ALLOW;
  }

  private async reloadTenantPolicies(tenantId: string): Promise<void> {
    const policies = await this.prisma.securityPolicy.findMany({
      where: {
        tenantId,
        enabled: true
      },
      orderBy: { priority: 'desc' }
    });

    this.policies.set(tenantId, policies);
  }

  private async logPolicyEvaluation(
    tenantId: string,
    context: any,
    matchedPolicies: SecurityPolicy[],
    action: PolicyAction
  ): Promise<void> {
    await this.prisma.auditLog.create({
      data: {
        tenantId,
        userId: context.userId,
        action: action === PolicyAction.DENY ? 'POLICY_VIOLATION' : 'POLICY_CHECK',
        resourceType: 'SECURITY_POLICY',
        resourceId: matchedPolicies[0]?.id,
        details: {
          context,
          matchedPolicies: matchedPolicies.map(p => p.name),
          action
        },
        ipAddress: context.ipAddress || 'unknown',
        userAgent: context.userAgent || 'policy-engine'
      }
    });
  }

  private async sendPolicyAlert(
    tenantId: string,
    context: any,
    matchedPolicies: SecurityPolicy[]
  ): Promise<void> {
    // Publish alert to Redis for alert service
    await this.redis.publish('policy:alert', JSON.stringify({
      tenantId,
      timestamp: new Date(),
      policies: matchedPolicies.map(p => ({
        id: p.id,
        name: p.name,
        type: p.type
      })),
      context
    }));
  }

  private convertPoliciesToYAML(policies: SecurityPolicy[]): string {
    // Simple YAML conversion
    let yaml = 'policies:\n';
    
    for (const policy of policies) {
      yaml += `  - name: ${policy.name}\n`;
      yaml += `    type: ${policy.type}\n`;
      yaml += `    enabled: ${policy.enabled}\n`;
      yaml += `    priority: ${policy.priority}\n`;
      yaml += `    rules:\n`;
      
      for (const rule of policy.rules) {
        yaml += `      - action: ${rule.action}\n`;
        yaml += `        condition:\n`;
        yaml += `          field: ${rule.condition.field}\n`;
        yaml += `          operator: ${rule.condition.operator}\n`;
        yaml += `          value: ${rule.condition.value}\n`;
      }
    }
    
    return yaml;
  }

  async isHealthy(): Promise<boolean> {
    try {
      // Check if policies are loaded
      return this.policies.size > 0 || (await this.loadPolicies(), true);
    } catch {
      return false;
    }
  }
}