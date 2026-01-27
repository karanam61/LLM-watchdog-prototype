
-- Insert default users for testing
-- Passwords are currently stored as plain text for demo simplicity (as per auth.py placeholder)
-- In production, replace with bcrypt hashes.

INSERT INTO users (username, password_hash, role, seniority) 
VALUES 
  ('analyst', 'analyst123', 'analyst', 'junior'),
  ('senior', 'senior123', 'analyst', 'senior'),
  ('dev', 'dev123', 'developer', 'senior'),
  ('admin', 'admin123', 'data_analyst', 'senior')
ON CONFLICT (username) DO NOTHING;
