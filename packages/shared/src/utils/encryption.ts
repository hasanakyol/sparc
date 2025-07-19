import crypto from 'crypto';

// Encryption configuration
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const TAG_LENGTH = 16;
const SALT_LENGTH = 32;
const KEY_LENGTH = 32;
const ITERATIONS = 100000;

// Get encryption key from environment or generate one
const getEncryptionKey = (): string => {
  const key = process.env.ENCRYPTION_KEY;
  if (!key) {
    throw new Error('ENCRYPTION_KEY environment variable is not set');
  }
  return key;
};

// Derive key from password using PBKDF2
const deriveKey = (password: string, salt: Buffer): Buffer => {
  return crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LENGTH, 'sha256');
};

// Encrypt data
export const encrypt = (data: string): string => {
  try {
    const password = getEncryptionKey();
    const salt = crypto.randomBytes(SALT_LENGTH);
    const key = deriveKey(password, salt);
    const iv = crypto.randomBytes(IV_LENGTH);
    
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    
    const encrypted = Buffer.concat([
      cipher.update(data, 'utf8'),
      cipher.final()
    ]);
    
    const tag = cipher.getAuthTag();
    
    // Combine salt, iv, tag, and encrypted data
    const combined = Buffer.concat([salt, iv, tag, encrypted]);
    
    return combined.toString('base64');
  } catch (error) {
    throw new Error(`Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
};

// Decrypt data
export const decrypt = (encryptedData: string): string => {
  try {
    const password = getEncryptionKey();
    const combined = Buffer.from(encryptedData, 'base64');
    
    // Extract components
    const salt = combined.slice(0, SALT_LENGTH);
    const iv = combined.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
    const tag = combined.slice(SALT_LENGTH + IV_LENGTH, SALT_LENGTH + IV_LENGTH + TAG_LENGTH);
    const encrypted = combined.slice(SALT_LENGTH + IV_LENGTH + TAG_LENGTH);
    
    const key = deriveKey(password, salt);
    
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);
    
    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final()
    ]);
    
    return decrypted.toString('utf8');
  } catch (error) {
    throw new Error(`Decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
};

// Hash sensitive data for indexing/searching
export const hash = (data: string): string => {
  const salt = process.env.HASH_SALT;
  if (!salt) {
    throw new Error('HASH_SALT environment variable is required');
  }
  return crypto
    .createHash('sha256')
    .update(data + salt)
    .digest('hex');
};

// Generate encryption key
export const generateEncryptionKey = (): string => {
  return crypto.randomBytes(32).toString('base64');
};

// Rotate encryption key
export const rotateEncryptionKey = async (
  oldKey: string,
  newKey: string,
  reencryptFunction: (oldKey: string, newKey: string) => Promise<void>
): Promise<void> => {
  // Store old key temporarily
  process.env.OLD_ENCRYPTION_KEY = oldKey;
  process.env.ENCRYPTION_KEY = newKey;
  
  try {
    // Call the provided reencrypt function
    await reencryptFunction(oldKey, newKey);
    
    // Clean up old key
    delete process.env.OLD_ENCRYPTION_KEY;
  } catch (error) {
    // Restore old key on failure
    process.env.ENCRYPTION_KEY = oldKey;
    delete process.env.OLD_ENCRYPTION_KEY;
    throw error;
  }
};

// Utility to check if a string is encrypted
export const isEncrypted = (data: string): boolean => {
  try {
    const buffer = Buffer.from(data, 'base64');
    // Check if the length is at least the minimum required
    return buffer.length >= SALT_LENGTH + IV_LENGTH + TAG_LENGTH + 1;
  } catch {
    return false;
  }
};