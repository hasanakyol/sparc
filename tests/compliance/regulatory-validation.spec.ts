import { describe, it, expect, beforeAll, afterAll, beforeEach } from '@jest/testing-library/jest-dom';
import { TestEnvironment } from '../utils/test-environment';
import { AuditService } from '../../services/audit-service/src/services/auditService';
import { ReportingService } from '../../services/reporting-service/src/services/reportingService';
import { ComplianceService } from '../../services/compliance-service/src/services/complianceService';
import { DatabaseService } from '../../services/shared/database/databaseService';
import { EncryptionService } from '../../services/shared/security/encryptionService';
import { AccessControlService } from '../../services/access-control-service/src/services/accessControlService';
import { UserService } from '../../services/user-service/src/services/userService';

interface AuditLog {
  id: string;
  timestamp: Date;
  userId: string;
  tenantId: string;
  action: string;
  resource: string;
  resourceId: string;
  ipAddress: string;
  userAgent: string;
  sessionId: string;
  outcome: 'SUCCESS' | 'FAILURE';
  details: Record<string, any>;
  dataClassification: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';
  complianceFlags: string[];
}

interface ComplianceReport {
  id: string;
  type: 'SOX' | 'HIPAA' | 'PCI_DSS';
  generatedAt: Date;
  period: { start: Date; end: Date };
  findings: ComplianceFinding[];
  status: 'COMPLIANT' | 'NON_COMPLIANT' | 'NEEDS_REVIEW';
}

interface ComplianceFinding {
  id: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  category: string;
  description: string;
  recommendation: string;
  evidence: string[];
}

describe('Regulatory Compliance Validation', () => {
  let testEnv: TestEnvironment;
  let auditService: AuditService;
  let reportingService: ReportingService;
  let complianceService: ComplianceService;
  let databaseService: DatabaseService;
  let encryptionService: EncryptionService;
  let accessControlService: AccessControlService;
  let userService: UserService;

  const TEST_TENANT_ID = 'compliance-test-tenant';
  const TEST_USER_ID = 'compliance-test-user';
  const COMPLIANCE_ADMIN_ID = 'compliance-admin-user';

  beforeAll(async () => {
    testEnv = new TestEnvironment();
    await testEnv.setup();

    auditService = testEnv.getService('audit');
    reportingService = testEnv.getService('reporting');
    complianceService = testEnv.getService('compliance');
    databaseService = testEnv.getService('database');
    encryptionService = testEnv.getService('encryption');
    accessControlService = testEnv.getService('accessControl');
    userService = testEnv.getService('user');

    // Setup test tenant and users
    await testEnv.createTestTenant(TEST_TENANT_ID);
    await testEnv.createTestUser(TEST_USER_ID, TEST_TENANT_ID);
    await testEnv.createTestUser(COMPLIANCE_ADMIN_ID, TEST_TENANT_ID, ['COMPLIANCE_ADMIN']);
  });

  afterAll(async () => {
    await testEnv.cleanup();
  });

  beforeEach(async () => {
    await testEnv.resetTestData();
  });

  describe('SOX Compliance Validation', () => {
    describe('Audit Logging Requirements', () => {
      it('should log all financial system access with required SOX fields', async () => {
        // Simulate financial system access
        const financialActions = [
          { action: 'VIEW_FINANCIAL_REPORT', resource: 'financial_reports', resourceId: 'report_123' },
          { action: 'MODIFY_FINANCIAL_DATA', resource: 'financial_records', resourceId: 'record_456' },
          { action: 'APPROVE_TRANSACTION', resource: 'transactions', resourceId: 'txn_789' },
          { action: 'EXPORT_FINANCIAL_DATA', resource: 'financial_exports', resourceId: 'export_101' }
        ];

        for (const actionData of financialActions) {
          await accessControlService.performAction(TEST_USER_ID, actionData.action, {
            resource: actionData.resource,
            resourceId: actionData.resourceId,
            tenantId: TEST_TENANT_ID
          });
        }

        // Verify audit logs contain SOX-required fields
        const auditLogs = await auditService.getAuditLogs({
          tenantId: TEST_TENANT_ID,
          userId: TEST_USER_ID,
          timeRange: { start: new Date(Date.now() - 3600000), end: new Date() }
        });

        expect(auditLogs.length).toBeGreaterThanOrEqual(financialActions.length);

        for (const log of auditLogs) {
          // SOX requires: who, what, when, where, authorization
          expect(log).toHaveProperty('userId');
          expect(log).toHaveProperty('action');
          expect(log).toHaveProperty('timestamp');
          expect(log).toHaveProperty('ipAddress');
          expect(log).toHaveProperty('sessionId');
          expect(log).toHaveProperty('outcome');
          expect(log).toHaveProperty('details.authorization');
          expect(log).toHaveProperty('details.businessJustification');
          
          // SOX-specific compliance flags
          expect(log.complianceFlags).toContain('SOX_APPLICABLE');
          expect(log.dataClassification).toBeOneOf(['CONFIDENTIAL', 'RESTRICTED']);
        }
      });

      it('should ensure audit logs are immutable and tamper-evident', async () => {
        // Create an audit log
        const originalLog = await auditService.createAuditLog({
          userId: TEST_USER_ID,
          tenantId: TEST_TENANT_ID,
          action: 'VIEW_FINANCIAL_REPORT',
          resource: 'financial_reports',
          resourceId: 'report_123',
          ipAddress: '192.168.1.100',
          userAgent: 'Test Browser',
          sessionId: 'session_123',
          outcome: 'SUCCESS',
          details: { reportType: 'quarterly_earnings' }
        });

        // Attempt to modify the audit log directly in database
        const modificationAttempt = async () => {
          await databaseService.query(
            'UPDATE audit_logs SET action = ? WHERE id = ?',
            ['MODIFIED_ACTION', originalLog.id]
          );
        };

        // Should fail due to immutability constraints
        await expect(modificationAttempt()).rejects.toThrow();

        // Verify log integrity using cryptographic hash
        const retrievedLog = await auditService.getAuditLog(originalLog.id);
        expect(retrievedLog.integrityHash).toBe(originalLog.integrityHash);
        
        // Verify digital signature
        const isValid = await encryptionService.verifySignature(
          retrievedLog.data,
          retrievedLog.digitalSignature
        );
        expect(isValid).toBe(true);
      });

      it('should maintain audit trail for 7+ years as required by SOX', async () => {
        // Create audit logs with various timestamps
        const testDates = [
          new Date('2017-01-01'), // 7+ years ago
          new Date('2020-06-15'), // 4 years ago
          new Date('2023-12-01'), // Recent
        ];

        const createdLogs = [];
        for (const date of testDates) {
          const log = await auditService.createAuditLog({
            userId: TEST_USER_ID,
            tenantId: TEST_TENANT_ID,
            action: 'VIEW_FINANCIAL_REPORT',
            resource: 'financial_reports',
            resourceId: `report_${date.getTime()}`,
            timestamp: date,
            ipAddress: '192.168.1.100',
            outcome: 'SUCCESS'
          });
          createdLogs.push(log);
        }

        // Verify retention policy
        const retentionPolicy = await complianceService.getRetentionPolicy('SOX');
        expect(retentionPolicy.minimumRetentionYears).toBeGreaterThanOrEqual(7);

        // Verify old logs are still accessible
        for (const log of createdLogs) {
          const retrievedLog = await auditService.getAuditLog(log.id);
          expect(retrievedLog).toBeDefined();
          expect(retrievedLog.id).toBe(log.id);
        }

        // Verify automated retention enforcement
        const retentionStatus = await complianceService.validateRetention('SOX', TEST_TENANT_ID);
        expect(retentionStatus.compliant).toBe(true);
        expect(retentionStatus.oldestRecord).toBeDefined();
      });
    });

    describe('Internal Controls Validation', () => {
      it('should enforce segregation of duties for financial operations', async () => {
        // Create users with different roles
        const preparerId = 'financial-preparer';
        const reviewerId = 'financial-reviewer';
        const approverId = 'financial-approver';

        await testEnv.createTestUser(preparerId, TEST_TENANT_ID, ['FINANCIAL_PREPARER']);
        await testEnv.createTestUser(reviewerId, TEST_TENANT_ID, ['FINANCIAL_REVIEWER']);
        await testEnv.createTestUser(approverId, TEST_TENANT_ID, ['FINANCIAL_APPROVER']);

        // Test segregation of duties workflow
        const transactionId = 'txn_sod_test';

        // Step 1: Preparer creates transaction
        const prepareResult = await accessControlService.performAction(preparerId, 'PREPARE_TRANSACTION', {
          resource: 'transactions',
          resourceId: transactionId,
          tenantId: TEST_TENANT_ID
        });
        expect(prepareResult.success).toBe(true);

        // Step 2: Same user cannot review their own transaction
        const selfReviewAttempt = await accessControlService.performAction(preparerId, 'REVIEW_TRANSACTION', {
          resource: 'transactions',
          resourceId: transactionId,
          tenantId: TEST_TENANT_ID
        });
        expect(selfReviewAttempt.success).toBe(false);
        expect(selfReviewAttempt.reason).toContain('segregation_of_duties');

        // Step 3: Different user can review
        const reviewResult = await accessControlService.performAction(reviewerId, 'REVIEW_TRANSACTION', {
          resource: 'transactions',
          resourceId: transactionId,
          tenantId: TEST_TENANT_ID
        });
        expect(reviewResult.success).toBe(true);

        // Step 4: Third user must approve
        const approveResult = await accessControlService.performAction(approverId, 'APPROVE_TRANSACTION', {
          resource: 'transactions',
          resourceId: transactionId,
          tenantId: TEST_TENANT_ID
        });
        expect(approveResult.success).toBe(true);

        // Verify audit trail shows proper segregation
        const auditLogs = await auditService.getAuditLogs({
          tenantId: TEST_TENANT_ID,
          resourceId: transactionId
        });

        const userIds = auditLogs.map(log => log.userId);
        const uniqueUsers = new Set(userIds);
        expect(uniqueUsers.size).toBeGreaterThanOrEqual(3); // At least 3 different users involved
      });

      it('should validate authorization controls for financial system access', async () => {
        // Test unauthorized access attempts
        const unauthorizedUser = 'unauthorized-user';
        await testEnv.createTestUser(unauthorizedUser, TEST_TENANT_ID, ['BASIC_USER']);

        const unauthorizedActions = [
          'MODIFY_FINANCIAL_DATA',
          'APPROVE_TRANSACTION',
          'EXPORT_FINANCIAL_DATA',
          'DELETE_FINANCIAL_RECORD'
        ];

        for (const action of unauthorizedActions) {
          const result = await accessControlService.performAction(unauthorizedUser, action, {
            resource: 'financial_reports',
            resourceId: 'report_123',
            tenantId: TEST_TENANT_ID
          });

          expect(result.success).toBe(false);
          expect(result.reason).toContain('insufficient_privileges');

          // Verify failed attempt is logged
          const auditLogs = await auditService.getAuditLogs({
            tenantId: TEST_TENANT_ID,
            userId: unauthorizedUser,
            outcome: 'FAILURE'
          });

          const relevantLog = auditLogs.find(log => log.action === action);
          expect(relevantLog).toBeDefined();
          expect(relevantLog.complianceFlags).toContain('SOX_VIOLATION_ATTEMPT');
        }
      });
    });

    describe('SOX Reporting Requirements', () => {
      it('should generate comprehensive SOX compliance reports', async () => {
        // Generate test data for reporting period
        const reportingPeriod = {
          start: new Date('2024-01-01'),
          end: new Date('2024-03-31')
        };

        // Create various financial activities
        const activities = [
          { action: 'CREATE_JOURNAL_ENTRY', count: 150 },
          { action: 'MODIFY_FINANCIAL_DATA', count: 75 },
          { action: 'APPROVE_TRANSACTION', count: 200 },
          { action: 'VIEW_FINANCIAL_REPORT', count: 500 }
        ];

        for (const activity of activities) {
          for (let i = 0; i < activity.count; i++) {
            await auditService.createAuditLog({
              userId: TEST_USER_ID,
              tenantId: TEST_TENANT_ID,
              action: activity.action,
              resource: 'financial_system',
              resourceId: `resource_${i}`,
              timestamp: new Date(reportingPeriod.start.getTime() + Math.random() * (reportingPeriod.end.getTime() - reportingPeriod.start.getTime())),
              outcome: Math.random() > 0.05 ? 'SUCCESS' : 'FAILURE', // 95% success rate
              complianceFlags: ['SOX_APPLICABLE']
            });
          }
        }

        // Generate SOX compliance report
        const soxReport = await reportingService.generateComplianceReport({
          type: 'SOX',
          tenantId: TEST_TENANT_ID,
          period: reportingPeriod,
          includeDetails: true
        });

        expect(soxReport).toBeDefined();
        expect(soxReport.type).toBe('SOX');
        expect(soxReport.period).toEqual(reportingPeriod);

        // Verify report contains required SOX sections
        expect(soxReport.sections).toHaveProperty('internalControls');
        expect(soxReport.sections).toHaveProperty('accessControls');
        expect(soxReport.sections).toHaveProperty('auditTrail');
        expect(soxReport.sections).toHaveProperty('segregationOfDuties');
        expect(soxReport.sections).toHaveProperty('dataIntegrity');

        // Verify metrics
        expect(soxReport.metrics.totalFinancialTransactions).toBeGreaterThan(0);
        expect(soxReport.metrics.failedAccessAttempts).toBeDefined();
        expect(soxReport.metrics.controlEffectiveness).toBeGreaterThan(0.95); // 95%+ effectiveness

        // Verify findings and recommendations
        expect(Array.isArray(soxReport.findings)).toBe(true);
        expect(soxReport.status).toBeOneOf(['COMPLIANT', 'NON_COMPLIANT', 'NEEDS_REVIEW']);
      });
    });
  });

  describe('HIPAA Compliance Validation', () => {
    describe('PHI Access Logging', () => {
      it('should log all PHI access with HIPAA-required fields', async () => {
        // Simulate PHI access scenarios
        const phiActions = [
          { action: 'VIEW_PATIENT_RECORD', resource: 'patient_records', resourceId: 'patient_123' },
          { action: 'MODIFY_PATIENT_DATA', resource: 'patient_records', resourceId: 'patient_456' },
          { action: 'EXPORT_PHI', resource: 'phi_exports', resourceId: 'export_789' },
          { action: 'PRINT_PATIENT_REPORT', resource: 'patient_reports', resourceId: 'report_101' }
        ];

        for (const actionData of phiActions) {
          await accessControlService.performAction(TEST_USER_ID, actionData.action, {
            resource: actionData.resource,
            resourceId: actionData.resourceId,
            tenantId: TEST_TENANT_ID,
            dataClassification: 'PHI'
          });
        }

        // Verify HIPAA audit logs
        const auditLogs = await auditService.getAuditLogs({
          tenantId: TEST_TENANT_ID,
          userId: TEST_USER_ID,
          dataClassification: 'PHI'
        });

        expect(auditLogs.length).toBeGreaterThanOrEqual(phiActions.length);

        for (const log of auditLogs) {
          // HIPAA requires: user identification, action, date/time, patient identifier
          expect(log).toHaveProperty('userId');
          expect(log).toHaveProperty('action');
          expect(log).toHaveProperty('timestamp');
          expect(log).toHaveProperty('resourceId'); // Patient identifier
          expect(log).toHaveProperty('details.accessReason');
          expect(log).toHaveProperty('details.minimumNecessary');
          
          // HIPAA-specific compliance flags
          expect(log.complianceFlags).toContain('HIPAA_PHI');
          expect(log.dataClassification).toBe('PHI');
        }
      });

      it('should enforce minimum necessary access principle', async () => {
        // Test that users can only access PHI they need for their job function
        const nurseUser = 'nurse-user';
        const billingUser = 'billing-user';
        const doctorUser = 'doctor-user';

        await testEnv.createTestUser(nurseUser, TEST_TENANT_ID, ['NURSE']);
        await testEnv.createTestUser(billingUser, TEST_TENANT_ID, ['BILLING_STAFF']);
        await testEnv.createTestUser(doctorUser, TEST_TENANT_ID, ['DOCTOR']);

        const patientId = 'patient_minimum_necessary_test';

        // Nurse should access clinical data but not billing
        const nurseAccessClinical = await accessControlService.performAction(nurseUser, 'VIEW_CLINICAL_DATA', {
          resource: 'patient_records',
          resourceId: patientId,
          tenantId: TEST_TENANT_ID
        });
        expect(nurseAccessClinical.success).toBe(true);

        const nurseAccessBilling = await accessControlService.performAction(nurseUser, 'VIEW_BILLING_DATA', {
          resource: 'patient_records',
          resourceId: patientId,
          tenantId: TEST_TENANT_ID
        });
        expect(nurseAccessBilling.success).toBe(false);

        // Billing staff should access billing data but not clinical details
        const billingAccessBilling = await accessControlService.performAction(billingUser, 'VIEW_BILLING_DATA', {
          resource: 'patient_records',
          resourceId: patientId,
          tenantId: TEST_TENANT_ID
        });
        expect(billingAccessBilling.success).toBe(true);

        const billingAccessClinical = await accessControlService.performAction(billingUser, 'VIEW_CLINICAL_DATA', {
          resource: 'patient_records',
          resourceId: patientId,
          tenantId: TEST_TENANT_ID
        });
        expect(billingAccessClinical.success).toBe(false);

        // Doctor should have broader access
        const doctorAccessClinical = await accessControlService.performAction(doctorUser, 'VIEW_CLINICAL_DATA', {
          resource: 'patient_records',
          resourceId: patientId,
          tenantId: TEST_TENANT_ID
        });
        expect(doctorAccessClinical.success).toBe(true);

        // Verify audit logs show minimum necessary compliance
        const auditLogs = await auditService.getAuditLogs({
          tenantId: TEST_TENANT_ID,
          resourceId: patientId
        });

        for (const log of auditLogs) {
          expect(log.details.minimumNecessaryJustification).toBeDefined();
          expect(log.details.jobFunction).toBeDefined();
        }
      });

      it('should maintain PHI audit logs for 6+ years as required by HIPAA', async () => {
        // Test HIPAA retention requirements
        const retentionPolicy = await complianceService.getRetentionPolicy('HIPAA');
        expect(retentionPolicy.minimumRetentionYears).toBeGreaterThanOrEqual(6);

        // Create PHI access logs with various timestamps
        const testDates = [
          new Date('2018-01-01'), // 6+ years ago
          new Date('2021-06-15'), // 3 years ago
          new Date('2024-01-01'), // Recent
        ];

        const createdLogs = [];
        for (const date of testDates) {
          const log = await auditService.createAuditLog({
            userId: TEST_USER_ID,
            tenantId: TEST_TENANT_ID,
            action: 'VIEW_PATIENT_RECORD',
            resource: 'patient_records',
            resourceId: `patient_${date.getTime()}`,
            timestamp: date,
            dataClassification: 'PHI',
            complianceFlags: ['HIPAA_PHI'],
            outcome: 'SUCCESS'
          });
          createdLogs.push(log);
        }

        // Verify all logs are still accessible
        for (const log of createdLogs) {
          const retrievedLog = await auditService.getAuditLog(log.id);
          expect(retrievedLog).toBeDefined();
          expect(retrievedLog.dataClassification).toBe('PHI');
        }
      });
    });

    describe('Privacy and Security Controls', () => {
      it('should encrypt PHI at rest and in transit', async () => {
        // Test PHI encryption requirements
        const phiData = {
          patientId: 'patient_encryption_test',
          firstName: 'John',
          lastName: 'Doe',
          ssn: '123-45-6789',
          medicalRecord: 'Confidential medical information'
        };

        // Store PHI data
        const storedRecord = await databaseService.storePHI(phiData, TEST_TENANT_ID);

        // Verify data is encrypted at rest
        const rawData = await databaseService.getRawRecord(storedRecord.id);
        expect(rawData.firstName).not.toBe(phiData.firstName); // Should be encrypted
        expect(rawData.ssn).not.toBe(phiData.ssn); // Should be encrypted

        // Verify encryption metadata
        expect(rawData.encryptionAlgorithm).toBe('AES-256-GCM');
        expect(rawData.keyId).toBeDefined();
        expect(rawData.encryptedAt).toBeDefined();

        // Verify data can be decrypted with proper authorization
        const decryptedData = await databaseService.getPHI(storedRecord.id, TEST_USER_ID);
        expect(decryptedData.firstName).toBe(phiData.firstName);
        expect(decryptedData.ssn).toBe(phiData.ssn);

        // Verify audit log for encryption/decryption
        const auditLogs = await auditService.getAuditLogs({
          resourceId: storedRecord.id,
          action: 'DECRYPT_PHI'
        });
        expect(auditLogs.length).toBeGreaterThan(0);
      });

      it('should implement proper access controls for PHI', async () => {
        // Test role-based access controls for PHI
        const patientId = 'patient_access_control_test';
        
        // Create users with different roles
        const roles = [
          { userId: 'doctor-1', roles: ['DOCTOR'], shouldAccess: true },
          { userId: 'nurse-1', roles: ['NURSE'], shouldAccess: true },
          { userId: 'admin-1', roles: ['ADMIN'], shouldAccess: false }, // Admin shouldn't access PHI without clinical need
          { userId: 'janitor-1', roles: ['FACILITIES'], shouldAccess: false }
        ];

        for (const roleTest of roles) {
          await testEnv.createTestUser(roleTest.userId, TEST_TENANT_ID, roleTest.roles);

          const accessResult = await accessControlService.performAction(roleTest.userId, 'VIEW_PATIENT_RECORD', {
            resource: 'patient_records',
            resourceId: patientId,
            tenantId: TEST_TENANT_ID
          });

          expect(accessResult.success).toBe(roleTest.shouldAccess);

          if (!roleTest.shouldAccess) {
            // Verify failed access is logged
            const auditLogs = await auditService.getAuditLogs({
              userId: roleTest.userId,
              outcome: 'FAILURE',
              action: 'VIEW_PATIENT_RECORD'
            });
            expect(auditLogs.length).toBeGreaterThan(0);
          }
        }
      });
    });

    describe('HIPAA Reporting Requirements', () => {
      it('should generate comprehensive HIPAA compliance reports', async () => {
        const reportingPeriod = {
          start: new Date('2024-01-01'),
          end: new Date('2024-03-31')
        };

        // Generate HIPAA compliance report
        const hipaaReport = await reportingService.generateComplianceReport({
          type: 'HIPAA',
          tenantId: TEST_TENANT_ID,
          period: reportingPeriod,
          includeDetails: true
        });

        expect(hipaaReport).toBeDefined();
        expect(hipaaReport.type).toBe('HIPAA');

        // Verify report contains required HIPAA sections
        expect(hipaaReport.sections).toHaveProperty('phiAccess');
        expect(hipaaReport.sections).toHaveProperty('privacyControls');
        expect(hipaaReport.sections).toHaveProperty('securityIncidents');
        expect(hipaaReport.sections).toHaveProperty('breachAssessment');
        expect(hipaaReport.sections).toHaveProperty('minimumNecessary');

        // Verify HIPAA-specific metrics
        expect(hipaaReport.metrics.phiAccessEvents).toBeDefined();
        expect(hipaaReport.metrics.unauthorizedAccessAttempts).toBeDefined();
        expect(hipaaReport.metrics.encryptionCompliance).toBeGreaterThan(0.99); // 99%+ encryption
      });
    });
  });

  describe('PCI-DSS Compliance Validation', () => {
    describe('Cardholder Data Protection', () => {
      it('should log all cardholder data access with PCI-DSS required fields', async () => {
        // Simulate cardholder data access
        const cardholderActions = [
          { action: 'VIEW_PAYMENT_DATA', resource: 'payment_records', resourceId: 'payment_123' },
          { action: 'PROCESS_PAYMENT', resource: 'payment_processing', resourceId: 'txn_456' },
          { action: 'EXPORT_PAYMENT_REPORT', resource: 'payment_reports', resourceId: 'report_789' },
          { action: 'REFUND_PAYMENT', resource: 'payment_processing', resourceId: 'refund_101' }
        ];

        for (const actionData of cardholderActions) {
          await accessControlService.performAction(TEST_USER_ID, actionData.action, {
            resource: actionData.resource,
            resourceId: actionData.resourceId,
            tenantId: TEST_TENANT_ID,
            dataClassification: 'CARDHOLDER_DATA'
          });
        }

        // Verify PCI-DSS audit logs
        const auditLogs = await auditService.getAuditLogs({
          tenantId: TEST_TENANT_ID,
          userId: TEST_USER_ID,
          dataClassification: 'CARDHOLDER_DATA'
        });

        expect(auditLogs.length).toBeGreaterThanOrEqual(cardholderActions.length);

        for (const log of auditLogs) {
          // PCI-DSS requires: user ID, type of event, date/time, success/failure, origination of event, identity of affected data
          expect(log).toHaveProperty('userId');
          expect(log).toHaveProperty('action'); // Type of event
          expect(log).toHaveProperty('timestamp');
          expect(log).toHaveProperty('outcome'); // Success/failure
          expect(log).toHaveProperty('ipAddress'); // Origination
          expect(log).toHaveProperty('resourceId'); // Affected data identity
          
          // PCI-DSS specific compliance flags
          expect(log.complianceFlags).toContain('PCI_DSS');
          expect(log.dataClassification).toBe('CARDHOLDER_DATA');
        }
      });

      it('should maintain cardholder data audit logs for 1+ year with 3 months immediately available', async () => {
        // Test PCI-DSS retention requirements
        const retentionPolicy = await complianceService.getRetentionPolicy('PCI_DSS');
        expect(retentionPolicy.minimumRetentionYears).toBeGreaterThanOrEqual(1);
        expect(retentionPolicy.immediateAccessMonths).toBeGreaterThanOrEqual(3);

        // Create payment audit logs with various timestamps
        const testDates = [
          new Date(Date.now() - 400 * 24 * 60 * 60 * 1000), // 400 days ago (> 1 year)
          new Date(Date.now() - 100 * 24 * 60 * 60 * 1000), // 100 days ago
          new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),  // 30 days ago
          new Date(), // Now
        ];

        const createdLogs = [];
        for (const date of testDates) {
          const log = await auditService.createAuditLog({
            userId: TEST_USER_ID,
            tenantId: TEST_TENANT_ID,
            action: 'PROCESS_PAYMENT',
            resource: 'payment_processing',
            resourceId: `payment_${date.getTime()}`,
            timestamp: date,
            dataClassification: 'CARDHOLDER_DATA',
            complianceFlags: ['PCI_DSS'],
            outcome: 'SUCCESS'
          });
          createdLogs.push(log);
        }

        // Verify all logs are accessible
        for (const log of createdLogs) {
          const retrievedLog = await auditService.getAuditLog(log.id);
          expect(retrievedLog).toBeDefined();
        }

        // Verify recent logs (3 months) have immediate access
        const recentLogs = await auditService.getAuditLogs({
          tenantId: TEST_TENANT_ID,
          dataClassification: 'CARDHOLDER_DATA',
          timeRange: {
            start: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000), // 3 months
            end: new Date()
          }
        });

        expect(recentLogs.length).toBeGreaterThan(0);
        for (const log of recentLogs) {
          expect(log.accessTier).toBe('IMMEDIATE');
        }
      });

      it('should encrypt cardholder data and protect encryption keys', async () => {
        // Test PCI-DSS encryption requirements
        const cardholderData = {
          cardNumber: '4111111111111111',
          expiryDate: '12/25',
          cvv: '123',
          cardholderName: 'John Doe'
        };

        // Store cardholder data
        const storedRecord = await databaseService.storeCardholderData(cardholderData, TEST_TENANT_ID);

        // Verify data is encrypted at rest
        const rawData = await databaseService.getRawRecord(storedRecord.id);
        expect(rawData.cardNumber).not.toBe(cardholderData.cardNumber); // Should be encrypted
        expect(rawData.cvv).not.toBe(cardholderData.cvv); // Should be encrypted

        // Verify strong encryption
        expect(rawData.encryptionAlgorithm).toBe('AES-256-GCM');
        expect(rawData.keyId).toBeDefined();

        // Verify key management
        const keyInfo = await encryptionService.getKeyInfo(rawData.keyId);
        expect(keyInfo.keyLength).toBeGreaterThanOrEqual(256);
        expect(keyInfo.rotationDate).toBeDefined();
        expect(keyInfo.accessControlled).toBe(true);

        // Verify data masking for display
        const maskedData = await databaseService.getCardholderDataMasked(storedRecord.id, TEST_USER_ID);
        expect(maskedData.cardNumber).toMatch(/\*{12}\d{4}/); // Should show only last 4 digits
        expect(maskedData.cvv).toBe('***');
      });
    });

    describe('Network Security Controls', () => {
      it('should validate network segmentation for cardholder data environment', async () => {
        // Test network segmentation requirements
        const networkConfig = await complianceService.getNetworkConfiguration(TEST_TENANT_ID);

        // Verify cardholder data environment (CDE) is segmented
        expect(networkConfig.cdeSegmentation).toBe(true);
        expect(networkConfig.firewallRules).toBeDefined();
        expect(networkConfig.networkZones).toContain('CDE');
        expect(networkConfig.networkZones).toContain('NON_CDE');

        // Verify access controls between zones
        const accessRules = networkConfig.accessRules;
        const cdeRules = accessRules.filter(rule => rule.destination === 'CDE');
        
        for (const rule of cdeRules) {
          expect(rule.protocol).toBeOneOf(['HTTPS', 'SSH']);
          expect(rule.authentication).toBe('REQUIRED');
          expect(rule.logging).toBe('ENABLED');
        }
      });

      it('should validate secure transmission of cardholder data', async () => {
        // Test secure transmission requirements
        const transmissionTest = await complianceService.validateSecureTransmission({
          tenantId: TEST_TENANT_ID,
          dataType: 'CARDHOLDER_DATA'
        });

        expect(transmissionTest.tlsVersion).toMatch(/^1\.[23]$/); // TLS 1.2 or 1.3
        expect(transmissionTest.cipherSuite).toBeDefined();
        expect(transmissionTest.certificateValid).toBe(true);
        expect(transmissionTest.weakCiphersDisabled).toBe(true);
      });
    });

    describe('PCI-DSS Reporting Requirements', () => {
      it('should generate comprehensive PCI-DSS compliance reports', async () => {
        const reportingPeriod = {
          start: new Date('2024-01-01'),
          end: new Date('2024-03-31')
        };

        // Generate PCI-DSS compliance report
        const pciReport = await reportingService.generateComplianceReport({
          type: 'PCI_DSS',
          tenantId: TEST_TENANT_ID,
          period: reportingPeriod,
          includeDetails: true
        });

        expect(pciReport).toBeDefined();
        expect(pciReport.type).toBe('PCI_DSS');

        // Verify report contains required PCI-DSS sections
        expect(pciReport.sections).toHaveProperty('cardholderDataProtection');
        expect(pciReport.sections).toHaveProperty('networkSecurity');
        expect(pciReport.sections).toHaveProperty('accessControls');
        expect(pciReport.sections).toHaveProperty('vulnerabilityManagement');
        expect(pciReport.sections).toHaveProperty('securityTesting');

        // Verify PCI-DSS specific metrics
        expect(pciReport.metrics.cardholderDataAccess).toBeDefined();
        expect(pciReport.metrics.encryptionCompliance).toBe(1.0); // 100% encryption required
        expect(pciReport.metrics.networkSegmentation).toBe(true);
        expect(pciReport.metrics.vulnerabilityScans).toBeDefined();
      });

      it('should validate quarterly vulnerability scans', async () => {
        // Test quarterly vulnerability scan requirements
        const vulnerabilityScans = await complianceService.getVulnerabilityScans({
          tenantId: TEST_TENANT_ID,
          timeRange: {
            start: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000), // Last year
            end: new Date()
          }
        });

        // Should have at least 4 scans in the last year (quarterly)
        expect(vulnerabilityScans.length).toBeGreaterThanOrEqual(4);

        for (const scan of vulnerabilityScans) {
          expect(scan.scanType).toBeOneOf(['INTERNAL', 'EXTERNAL']);
          expect(scan.status).toBe('COMPLETED');
          expect(scan.findings).toBeDefined();
          expect(scan.remediationStatus).toBeDefined();
        }

        // Verify latest scan is recent (within last 3 months)
        const latestScan = vulnerabilityScans[0];
        const threeMonthsAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
        expect(latestScan.completedAt).toBeAfter(threeMonthsAgo);
      });
    });
  });

  describe('Cross-Compliance Integration Tests', () => {
    it('should handle multi-compliance scenarios correctly', async () => {
      // Test scenario where data falls under multiple compliance frameworks
      const multiComplianceData = {
        patientId: 'patient_multi_compliance',
        paymentMethod: 'credit_card',
        financialAccount: 'account_123'
      };

      // Access data that triggers multiple compliance requirements
      const accessResult = await accessControlService.performAction(TEST_USER_ID, 'VIEW_PATIENT_BILLING', {
        resource: 'patient_billing',
        resourceId: multiComplianceData.patientId,
        tenantId: TEST_TENANT_ID,
        dataClassifications: ['PHI', 'CARDHOLDER_DATA', 'FINANCIAL_DATA']
      });

      expect(accessResult.success).toBe(true);

      // Verify audit log contains all relevant compliance flags
      const auditLogs = await auditService.getAuditLogs({
        tenantId: TEST_TENANT_ID,
        userId: TEST_USER_ID,
        resourceId: multiComplianceData.patientId
      });

      const relevantLog = auditLogs[0];
      expect(relevantLog.complianceFlags).toContain('HIPAA_PHI');
      expect(relevantLog.complianceFlags).toContain('PCI_DSS');
      expect(relevantLog.complianceFlags).toContain('SOX_APPLICABLE');

      // Verify retention policy uses the most restrictive requirement
      const retentionPolicy = await complianceService.getRetentionPolicy('MULTI_COMPLIANCE');
      expect(retentionPolicy.minimumRetentionYears).toBe(7); // SOX requirement (most restrictive)
    });

    it('should generate unified compliance dashboard', async () => {
      // Test unified compliance reporting
      const unifiedReport = await reportingService.generateUnifiedComplianceReport({
        tenantId: TEST_TENANT_ID,
        frameworks: ['SOX', 'HIPAA', 'PCI_DSS'],
        period: {
          start: new Date('2024-01-01'),
          end: new Date('2024-03-31')
        }
      });

      expect(unifiedReport).toBeDefined();
      expect(unifiedReport.frameworks).toEqual(['SOX', 'HIPAA', 'PCI_DSS']);

      // Verify cross-compliance metrics
      expect(unifiedReport.crossComplianceMetrics).toBeDefined();
      expect(unifiedReport.crossComplianceMetrics.overallComplianceScore).toBeGreaterThan(0);
      expect(unifiedReport.crossComplianceMetrics.criticalFindings).toBeDefined();

      // Verify framework-specific sections
      expect(unifiedReport.frameworkReports.SOX).toBeDefined();
      expect(unifiedReport.frameworkReports.HIPAA).toBeDefined();
      expect(unifiedReport.frameworkReports.PCI_DSS).toBeDefined();
    });

    it('should validate data classification and handling consistency', async () => {
      // Test that data classification is consistent across all compliance frameworks
      const dataClassifications = await complianceService.getDataClassifications(TEST_TENANT_ID);

      // Verify all required classifications exist
      const requiredClassifications = ['PHI', 'CARDHOLDER_DATA', 'FINANCIAL_DATA', 'PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED'];
      for (const classification of requiredClassifications) {
        expect(dataClassifications).toContain(classification);
      }

      // Verify handling policies are defined for each classification
      for (const classification of dataClassifications) {
        const handlingPolicy = await complianceService.getDataHandlingPolicy(classification);
        expect(handlingPolicy).toBeDefined();
        expect(handlingPolicy.encryptionRequired).toBeDefined();
        expect(handlingPolicy.accessControls).toBeDefined();
        expect(handlingPolicy.retentionPeriod).toBeDefined();
        expect(handlingPolicy.auditingRequired).toBeDefined();
      }
    });
  });

  describe('Compliance Monitoring and Alerting', () => {
    it('should detect and alert on compliance violations', async () => {
      // Test real-time compliance monitoring
      const violations = [
        {
          type: 'UNAUTHORIZED_PHI_ACCESS',
          simulate: async () => {
            // Attempt to access PHI without proper authorization
            await accessControlService.performAction('unauthorized-user', 'VIEW_PATIENT_RECORD', {
              resource: 'patient_records',
              resourceId: 'patient_violation_test',
              tenantId: TEST_TENANT_ID
            });
          }
        },
        {
          type: 'EXCESSIVE_FAILED_LOGINS',
          simulate: async () => {
            // Simulate multiple failed login attempts
            for (let i = 0; i < 10; i++) {
              await userService.authenticate('test-user', 'wrong-password', TEST_TENANT_ID);
            }
          }
        },
        {
          type: 'UNUSUAL_DATA_ACCESS_PATTERN',
          simulate: async () => {
            // Simulate unusual access pattern (bulk data access)
            for (let i = 0; i < 100; i++) {
              await accessControlService.performAction(TEST_USER_ID, 'VIEW_PATIENT_RECORD', {
                resource: 'patient_records',
                resourceId: `patient_${i}`,
                tenantId: TEST_TENANT_ID
              });
            }
          }
        }
      ];

      for (const violation of violations) {
        // Clear previous alerts
        await complianceService.clearAlerts(TEST_TENANT_ID);

        // Simulate violation
        await violation.simulate();

        // Wait for monitoring system to detect violation
        await new Promise(resolve => setTimeout(resolve, 2000));

        // Verify alert was generated
        const alerts = await complianceService.getAlerts({
          tenantId: TEST_TENANT_ID,
          type: violation.type,
          timeRange: { start: new Date(Date.now() - 60000), end: new Date() }
        });

        expect(alerts.length).toBeGreaterThan(0);
        
        const alert = alerts[0];
        expect(alert.severity).toBeOneOf(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
        expect(alert.complianceFrameworks).toBeDefined();
        expect(alert.recommendedActions).toBeDefined();
      }
    });

    it('should provide compliance metrics and KPIs', async () => {
      // Test compliance metrics calculation
      const metrics = await complianceService.getComplianceMetrics({
        tenantId: TEST_TENANT_ID,
        timeRange: {
          start: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // Last 30 days
          end: new Date()
        }
      });

      expect(metrics).toBeDefined();

      // Verify SOX metrics
      expect(metrics.sox).toHaveProperty('controlEffectiveness');
      expect(metrics.sox).toHaveProperty('segregationOfDutiesCompliance');
      expect(metrics.sox).toHaveProperty('auditTrailCompleteness');

      // Verify HIPAA metrics
      expect(metrics.hipaa).toHaveProperty('phiAccessCompliance');
      expect(metrics.hipaa).toHaveProperty('minimumNecessaryCompliance');
      expect(metrics.hipaa).toHaveProperty('encryptionCompliance');

      // Verify PCI-DSS metrics
      expect(metrics.pciDss).toHaveProperty('cardholderDataProtection');
      expect(metrics.pciDss).toHaveProperty('networkSecurityCompliance');
      expect(metrics.pciDss).toHaveProperty('vulnerabilityManagement');

      // Verify overall compliance score
      expect(metrics.overall).toHaveProperty('complianceScore');
      expect(metrics.overall.complianceScore).toBeGreaterThanOrEqual(0);
      expect(metrics.overall.complianceScore).toBeLessThanOrEqual(100);
    });
  });
});