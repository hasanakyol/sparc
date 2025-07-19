import { encrypt, decrypt, hash, isEncrypted } from './encryption';
import type { Credential, MobileCredential, IntegrationConfiguration } from '@prisma/client';

// Credential encryption/decryption service
export class CredentialService {
  // Encrypt credential data before saving
  static encryptCredential(credential: Partial<Credential>): Partial<Credential> {
    const encrypted = { ...credential };
    
    // Encrypt PIN code
    if (credential.pinCode && !isEncrypted(credential.pinCode)) {
      encrypted.pinCode = encrypt(credential.pinCode);
      encrypted.pinCodeHash = hash(credential.pinCode);
    }
    
    // Encrypt biometric template
    if (credential.biometricTemplate && !isEncrypted(credential.biometricTemplate)) {
      encrypted.biometricTemplate = encrypt(credential.biometricTemplate);
    }
    
    // Add card number hash for searching
    if (credential.cardNumber && !encrypted.cardNumberHash) {
      encrypted.cardNumberHash = hash(credential.cardNumber);
    }
    
    return encrypted;
  }
  
  // Decrypt credential data after reading
  static decryptCredential(credential: Credential): Credential {
    const decrypted = { ...credential };
    
    // Decrypt PIN code
    if (credential.pinCode && isEncrypted(credential.pinCode)) {
      try {
        decrypted.pinCode = decrypt(credential.pinCode);
      } catch (error) {
        console.error('Failed to decrypt PIN code:', error);
        decrypted.pinCode = null;
      }
    }
    
    // Decrypt biometric template
    if (credential.biometricTemplate && isEncrypted(credential.biometricTemplate)) {
      try {
        decrypted.biometricTemplate = decrypt(credential.biometricTemplate);
      } catch (error) {
        console.error('Failed to decrypt biometric template:', error);
        decrypted.biometricTemplate = null;
      }
    }
    
    return decrypted;
  }
  
  // Validate PIN code against hash
  static validatePinCode(plainPinCode: string, hashedPinCode: string): boolean {
    return hash(plainPinCode) === hashedPinCode;
  }
  
  // Find credential by card number using hash
  static getCardNumberSearchHash(cardNumber: string): string {
    return hash(cardNumber);
  }
}

// Mobile credential encryption/decryption service
export class MobileCredentialService {
  // Encrypt mobile credential data before saving
  static encryptMobileCredential(credential: Partial<MobileCredential>): Partial<MobileCredential> {
    const encrypted = { ...credential };
    
    // Encrypt credential data
    if (credential.credentialData && !isEncrypted(credential.credentialData)) {
      encrypted.credentialData = encrypt(credential.credentialData);
    }
    
    // Add device ID hash for searching
    if (credential.deviceId && !encrypted.deviceIdHash) {
      encrypted.deviceIdHash = hash(credential.deviceId);
    }
    
    return encrypted;
  }
  
  // Decrypt mobile credential data after reading
  static decryptMobileCredential(credential: MobileCredential): MobileCredential {
    const decrypted = { ...credential };
    
    // Decrypt credential data
    if (credential.credentialData && isEncrypted(credential.credentialData)) {
      try {
        decrypted.credentialData = decrypt(credential.credentialData);
      } catch (error) {
        console.error('Failed to decrypt mobile credential data:', error);
        throw new Error('Unable to decrypt mobile credential');
      }
    }
    
    return decrypted;
  }
  
  // Find mobile credential by device ID using hash
  static getDeviceIdSearchHash(deviceId: string): string {
    return hash(deviceId);
  }
}

// Integration configuration encryption/decryption service
export class IntegrationService {
  // Encrypt integration authentication data before saving
  static encryptIntegration(integration: Partial<IntegrationConfiguration>): Partial<IntegrationConfiguration> {
    const encrypted = { ...integration };
    
    // Encrypt authentication data
    if (integration.authentication) {
      const authStr = typeof integration.authentication === 'string' 
        ? integration.authentication 
        : JSON.stringify(integration.authentication);
        
      if (!isEncrypted(authStr)) {
        encrypted.authentication = encrypt(authStr);
      }
    }
    
    return encrypted;
  }
  
  // Decrypt integration authentication data after reading
  static decryptIntegration(integration: IntegrationConfiguration): IntegrationConfiguration {
    const decrypted = { ...integration };
    
    // Decrypt authentication data
    if (integration.authentication && isEncrypted(integration.authentication)) {
      try {
        const decryptedStr = decrypt(integration.authentication);
        // Try to parse as JSON, otherwise return as string
        try {
          decrypted.authentication = JSON.parse(decryptedStr);
        } catch {
          decrypted.authentication = decryptedStr;
        }
      } catch (error) {
        console.error('Failed to decrypt integration authentication:', error);
        decrypted.authentication = '{}';
      }
    }
    
    return decrypted;
  }
}

// Prisma middleware for automatic encryption/decryption
export function createEncryptionMiddleware() {
  return {
    async $use(params: any, next: any) {
      // Encrypt data before create/update
      if (params.model === 'Credential') {
        if (params.action === 'create' || params.action === 'update' || params.action === 'upsert') {
          if (params.args.data) {
            params.args.data = CredentialService.encryptCredential(params.args.data);
          }
        }
      } else if (params.model === 'MobileCredential') {
        if (params.action === 'create' || params.action === 'update' || params.action === 'upsert') {
          if (params.args.data) {
            params.args.data = MobileCredentialService.encryptMobileCredential(params.args.data);
          }
        }
      } else if (params.model === 'IntegrationConfiguration') {
        if (params.action === 'create' || params.action === 'update' || params.action === 'upsert') {
          if (params.args.data) {
            params.args.data = IntegrationService.encryptIntegration(params.args.data);
          }
        }
      }
      
      // Execute the query
      const result = await next(params);
      
      // Decrypt data after read
      if (params.model === 'Credential') {
        if (params.action === 'findUnique' || params.action === 'findFirst') {
          if (result) {
            return CredentialService.decryptCredential(result);
          }
        } else if (params.action === 'findMany') {
          return result.map((item: Credential) => CredentialService.decryptCredential(item));
        }
      } else if (params.model === 'MobileCredential') {
        if (params.action === 'findUnique' || params.action === 'findFirst') {
          if (result) {
            return MobileCredentialService.decryptMobileCredential(result);
          }
        } else if (params.action === 'findMany') {
          return result.map((item: MobileCredential) => MobileCredentialService.decryptMobileCredential(item));
        }
      } else if (params.model === 'IntegrationConfiguration') {
        if (params.action === 'findUnique' || params.action === 'findFirst') {
          if (result) {
            return IntegrationService.decryptIntegration(result);
          }
        } else if (params.action === 'findMany') {
          return result.map((item: IntegrationConfiguration) => IntegrationService.decryptIntegration(item));
        }
      }
      
      return result;
    }
  };
}