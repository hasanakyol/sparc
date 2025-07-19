import { PrismaClient } from '@prisma/client';
import { encrypt, decrypt, hash, isEncrypted } from './encryption';

const prisma = new PrismaClient();

interface MigrationResult {
  credentials: {
    total: number;
    encrypted: number;
    failed: number;
  };
  mobileCredentials: {
    total: number;
    encrypted: number;
    failed: number;
  };
  integrations: {
    total: number;
    encrypted: number;
    failed: number;
  };
}

export async function encryptExistingData(): Promise<MigrationResult> {
  const result: MigrationResult = {
    credentials: { total: 0, encrypted: 0, failed: 0 },
    mobileCredentials: { total: 0, encrypted: 0, failed: 0 },
    integrations: { total: 0, encrypted: 0, failed: 0 }
  };

  try {
    // Encrypt credentials
    console.log('Starting credential encryption...');
    const credentials = await prisma.credential.findMany();
    result.credentials.total = credentials.length;

    for (const credential of credentials) {
      try {
        const updates: any = { encryptionVersion: 1 };
        
        // Encrypt PIN code if exists and not already encrypted
        if (credential.pinCode && !isEncrypted(credential.pinCode)) {
          updates.pinCode = encrypt(credential.pinCode);
          updates.pinCodeHash = hash(credential.pinCode);
        }
        
        // Encrypt biometric template if exists and not already encrypted
        if (credential.biometricTemplate && !isEncrypted(credential.biometricTemplate)) {
          updates.biometricTemplate = encrypt(credential.biometricTemplate);
        }
        
        // Add card number hash for searching
        if (credential.cardNumber && !credential.cardNumberHash) {
          updates.cardNumberHash = hash(credential.cardNumber);
        }
        
        await prisma.credential.update({
          where: { id: credential.id },
          data: updates
        });
        
        result.credentials.encrypted++;
      } catch (error) {
        console.error(`Failed to encrypt credential ${credential.id}:`, error);
        result.credentials.failed++;
      }
    }

    // Encrypt mobile credentials
    console.log('Starting mobile credential encryption...');
    const mobileCredentials = await prisma.mobileCredential.findMany();
    result.mobileCredentials.total = mobileCredentials.length;

    for (const mobileCredential of mobileCredentials) {
      try {
        const updates: any = { encryptionVersion: 1 };
        
        // Encrypt credential data if not already encrypted
        if (mobileCredential.credentialData && !isEncrypted(mobileCredential.credentialData)) {
          updates.credentialData = encrypt(mobileCredential.credentialData);
        }
        
        // Add device ID hash for searching
        if (mobileCredential.deviceId && !mobileCredential.deviceIdHash) {
          updates.deviceIdHash = hash(mobileCredential.deviceId);
        }
        
        await prisma.mobileCredential.update({
          where: { id: mobileCredential.id },
          data: updates
        });
        
        result.mobileCredentials.encrypted++;
      } catch (error) {
        console.error(`Failed to encrypt mobile credential ${mobileCredential.id}:`, error);
        result.mobileCredentials.failed++;
      }
    }

    // Encrypt integration configurations
    console.log('Starting integration configuration encryption...');
    const integrations = await prisma.integrationConfiguration.findMany();
    result.integrations.total = integrations.length;

    for (const integration of integrations) {
      try {
        const updates: any = { encryptionVersion: 1 };
        
        // Parse authentication JSON and encrypt if not already encrypted
        if (integration.authentication) {
          const authStr = typeof integration.authentication === 'string' 
            ? integration.authentication 
            : JSON.stringify(integration.authentication);
            
          if (!isEncrypted(authStr)) {
            updates.authentication = encrypt(authStr);
          }
        }
        
        await prisma.integrationConfiguration.update({
          where: { id: integration.id },
          data: updates
        });
        
        result.integrations.encrypted++;
      } catch (error) {
        console.error(`Failed to encrypt integration ${integration.id}:`, error);
        result.integrations.failed++;
      }
    }

    console.log('Encryption migration completed:', result);
    return result;
  } finally {
    await prisma.$disconnect();
  }
}

export async function decryptForKeyRotation(oldKey: string, newKey: string): Promise<void> {
  // Temporarily set the old key for decryption
  process.env.OLD_ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
  process.env.ENCRYPTION_KEY = oldKey;

  try {
    // Re-encrypt credentials
    const credentials = await prisma.credential.findMany({
      where: { encryptionVersion: 1 }
    });

    for (const credential of credentials) {
      const updates: any = { encryptionVersion: 2 };
      
      if (credential.pinCode && isEncrypted(credential.pinCode)) {
        const decrypted = decrypt(credential.pinCode);
        process.env.ENCRYPTION_KEY = newKey;
        updates.pinCode = encrypt(decrypted);
        process.env.ENCRYPTION_KEY = oldKey;
      }
      
      if (credential.biometricTemplate && isEncrypted(credential.biometricTemplate)) {
        const decrypted = decrypt(credential.biometricTemplate);
        process.env.ENCRYPTION_KEY = newKey;
        updates.biometricTemplate = encrypt(decrypted);
        process.env.ENCRYPTION_KEY = oldKey;
      }
      
      await prisma.credential.update({
        where: { id: credential.id },
        data: updates
      });
    }

    // Re-encrypt mobile credentials
    const mobileCredentials = await prisma.mobileCredential.findMany({
      where: { encryptionVersion: 1 }
    });

    for (const mobileCredential of mobileCredentials) {
      const updates: any = { encryptionVersion: 2 };
      
      if (mobileCredential.credentialData && isEncrypted(mobileCredential.credentialData)) {
        const decrypted = decrypt(mobileCredential.credentialData);
        process.env.ENCRYPTION_KEY = newKey;
        updates.credentialData = encrypt(decrypted);
        process.env.ENCRYPTION_KEY = oldKey;
      }
      
      await prisma.mobileCredential.update({
        where: { id: mobileCredential.id },
        data: updates
      });
    }

    // Re-encrypt integration configurations
    const integrations = await prisma.integrationConfiguration.findMany({
      where: { encryptionVersion: 1 }
    });

    for (const integration of integrations) {
      const updates: any = { encryptionVersion: 2 };
      
      if (integration.authentication && isEncrypted(integration.authentication)) {
        const decrypted = decrypt(integration.authentication);
        process.env.ENCRYPTION_KEY = newKey;
        updates.authentication = encrypt(decrypted);
        process.env.ENCRYPTION_KEY = oldKey;
      }
      
      await prisma.integrationConfiguration.update({
        where: { id: integration.id },
        data: updates
      });
    }

    // Set the new key as active
    process.env.ENCRYPTION_KEY = newKey;
    delete process.env.OLD_ENCRYPTION_KEY;
  } catch (error) {
    // Restore original key on error
    process.env.ENCRYPTION_KEY = process.env.OLD_ENCRYPTION_KEY!;
    delete process.env.OLD_ENCRYPTION_KEY;
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

// CLI script
if (require.main === module) {
  const command = process.argv[2];
  
  if (command === 'encrypt') {
    encryptExistingData()
      .then(result => {
        console.log('Encryption completed successfully:', result);
        process.exit(0);
      })
      .catch(error => {
        console.error('Encryption failed:', error);
        process.exit(1);
      });
  } else if (command === 'rotate') {
    const oldKey = process.argv[3];
    const newKey = process.argv[4];
    
    if (!oldKey || !newKey) {
      console.error('Usage: ts-node encrypt-migration.ts rotate <old-key> <new-key>');
      process.exit(1);
    }
    
    decryptForKeyRotation(oldKey, newKey)
      .then(() => {
        console.log('Key rotation completed successfully');
        process.exit(0);
      })
      .catch(error => {
        console.error('Key rotation failed:', error);
        process.exit(1);
      });
  } else {
    console.error('Usage: ts-node encrypt-migration.ts [encrypt|rotate]');
    process.exit(1);
  }
}