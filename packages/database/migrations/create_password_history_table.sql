-- Create password history table for tracking password reuse
CREATE TABLE IF NOT EXISTS password_history (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  
  -- Index for efficient lookups
  INDEX idx_password_history_user_id (user_id),
  INDEX idx_password_history_created_at (user_id, created_at DESC)
);

-- Add password policy columns to users table
ALTER TABLE users
ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN IF NOT EXISTS password_expires_at TIMESTAMP WITH TIME ZONE,
ADD COLUMN IF NOT EXISTS force_password_change BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP WITH TIME ZONE;

-- Create index for password expiration queries
CREATE INDEX IF NOT EXISTS idx_users_password_expires_at ON users(password_expires_at)
WHERE password_expires_at IS NOT NULL;

-- Create index for locked accounts
CREATE INDEX IF NOT EXISTS idx_users_locked_until ON users(locked_until)
WHERE locked_until IS NOT NULL;

-- Function to clean up old password history entries
CREATE OR REPLACE FUNCTION cleanup_password_history()
RETURNS void AS $$
BEGIN
  -- Keep only the most recent N entries per user (configurable per tenant)
  DELETE FROM password_history
  WHERE id IN (
    SELECT id FROM (
      SELECT 
        id,
        ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY created_at DESC) as rn
      FROM password_history
    ) ranked
    WHERE rn > 10 -- Keep max 10 entries per user
  );
END;
$$ LANGUAGE plpgsql;

-- Schedule periodic cleanup (requires pg_cron extension)
-- SELECT cron.schedule('cleanup-password-history', '0 2 * * *', 'SELECT cleanup_password_history()');

-- Add comment to document the table
COMMENT ON TABLE password_history IS 'Tracks password history to prevent password reuse';
COMMENT ON COLUMN password_history.user_id IS 'Reference to the user who changed their password';
COMMENT ON COLUMN password_history.password_hash IS 'Bcrypt hash of the historical password';
COMMENT ON COLUMN password_history.created_at IS 'When this password was set';