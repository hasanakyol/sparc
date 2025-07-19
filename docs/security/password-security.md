# Enhanced Password Security Implementation

## Overview

SPARC now implements enterprise-grade password security with the following features:
- Minimum 12 character requirement
- Complexity validation
- Password history tracking (prevents reuse)
- Breach database checking via Have I Been Pwned API
- Secure password generation
- Password strength scoring

## Password Requirements

### Minimum Requirements
- **Length**: At least 12 characters
- **Uppercase**: At least one uppercase letter (A-Z)
- **Lowercase**: At least one lowercase letter (a-z)
- **Numbers**: At least one digit (0-9)
- **Special Characters**: At least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)

### Additional Validations
- No common patterns (e.g., "123456", "qwerty", "password")
- No sequential characters (e.g., "abcdef", "123456")
- No repeated characters (e.g., "aaaaaa")
- Cannot contain username or email
- Cannot match any of the last 5 passwords
- Checked against known breach databases

## Implementation Details

### Password Security Service

The `PasswordSecurityService` provides centralized password management:

```typescript
import { PasswordSecurityService } from '@sparc/shared/utils/password-security';

const passwordSecurity = new PasswordSecurityService(prisma, {
  passwordHistoryLimit: 5,
  breachCheckEndpoint: 'https://api.pwnedpasswords.com/range/'
});
```

### Validating Passwords

```typescript
// Validate a new password
const validation = await passwordSecurity.validatePassword(password, userId);
if (!validation.valid) {
  return {
    error: 'Password does not meet requirements',
    details: validation.errors
  };
}
```

### Password History

Password history is automatically tracked to prevent reuse:

```typescript
// After successful password change
await passwordSecurity.addToPasswordHistory(userId, hashedPassword);
```

### Breach Detection

Passwords are checked against the Have I Been Pwned database using k-anonymity:

```typescript
const isBreached = await passwordSecurity.checkPasswordBreach(password);
if (isBreached) {
  return { error: 'This password has been found in a data breach' };
}
```

## Database Schema

### Password History Table

```sql
CREATE TABLE password_history (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id),
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_password_history_user_id (user_id)
);
```

### User Table Additions

```sql
ALTER TABLE users ADD COLUMN password_changed_at TIMESTAMP;
ALTER TABLE users ADD COLUMN password_expires_at TIMESTAMP;
ALTER TABLE users ADD COLUMN force_password_change BOOLEAN DEFAULT FALSE;
```

## API Endpoints

### Signup
- Validates password against all requirements
- Checks breach database
- Creates initial password history entry

### Change Password
- Validates new password
- Checks against password history
- Checks breach database
- Updates password history
- Invalidates all sessions except current

### Reset Password
- Same validations as change password
- Clears reset token after successful change

## Security Best Practices

### 1. Password Storage
- Passwords hashed using bcrypt with 12 rounds
- Never store plaintext passwords
- Password history stores only hashes

### 2. Breach Detection
- Uses k-anonymity to protect password privacy
- Only first 5 characters of SHA-1 hash sent to API
- No full password ever leaves the system

### 3. Rate Limiting
- Password validation endpoints are rate-limited
- Prevents brute force attacks
- Exponential backoff for failed attempts

### 4. Session Management
- All sessions invalidated on password change
- User must re-authenticate with new password
- Prevents session hijacking after compromise

## Configuration

### Environment Variables
```bash
# Password policy
PASSWORD_MIN_LENGTH=12
PASSWORD_HISTORY_LIMIT=5
PASSWORD_MAX_AGE_DAYS=90

# Breach checking
HIBP_API_KEY=your-api-key-here
ENABLE_BREACH_CHECK=true
```

### Policy Customization

```typescript
const passwordPolicy = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
  preventReuse: 5,
  maxAge: 90, // days
  checkBreaches: true
};
```

## User Experience

### Password Strength Indicator

```typescript
const strength = passwordSecurity.calculatePasswordStrength(password);
// Returns: { score: 0-100, strength: 'weak'|'fair'|'good'|'strong', feedback: [] }
```

### Error Messages

Clear, actionable error messages help users create compliant passwords:

- "Password must be at least 12 characters long"
- "Password must contain at least one uppercase letter"
- "This password has been found in a data breach"
- "Password has been used recently. Please choose a different password"

### Password Generation

For users who want system-generated passwords:

```typescript
const securePassword = passwordSecurity.generateSecurePassword(16);
// Returns: "K9#mP2$vL6^nQ8@r"
```

## Migration Guide

### For Existing Users

1. Existing passwords remain valid until changed
2. On next password change, new requirements enforced
3. Optional: Force password reset for all users

### Database Migration

```bash
# Apply password history table
npm run db:migrate -- --migration=create_password_history_table

# Update user passwords to meet new requirements (optional)
npm run scripts:force-password-reset -- --all-users
```

## Monitoring

### Metrics to Track

1. **Password Validation Failures**
   - By failure reason
   - By user/tenant

2. **Breach Detections**
   - Count of breached passwords blocked
   - API availability

3. **Password Age**
   - Users with expired passwords
   - Average password age by tenant

### Audit Logging

All password-related events are logged:
- Password changes
- Failed validation attempts
- Breach detections
- Policy violations

## Testing

### Unit Tests

```typescript
describe('PasswordSecurityService', () => {
  it('should reject passwords under 12 characters', async () => {
    const result = await passwordSecurity.validatePassword('Short1!');
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('Password must be at least 12 characters long');
  });

  it('should detect breached passwords', async () => {
    const result = await passwordSecurity.checkPasswordBreach('password123');
    expect(result).toBe(true);
  });
});
```

### Integration Tests

- Test full signup flow with password validation
- Test password change with history check
- Test breach API integration

## Compliance

This implementation helps meet requirements for:
- **SOC 2**: Strong authentication controls
- **ISO 27001**: Access control requirements
- **NIST 800-63B**: Digital identity guidelines
- **PCI DSS**: Strong cryptography requirements

## Future Enhancements

1. **Passwordless Authentication**
   - WebAuthn/FIDO2 support
   - Biometric authentication

2. **Advanced Breach Detection**
   - Real-time breach monitoring
   - Proactive user notifications

3. **Adaptive Security**
   - Risk-based authentication
   - Behavioral analysis

4. **Enterprise Features**
   - Custom password policies per tenant
   - Delegated administration
   - Password expiration policies