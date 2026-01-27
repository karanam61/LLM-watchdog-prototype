
-- Users Table for RBAC
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('analyst', 'developer', 'data_analyst')),
    seniority TEXT NOT NULL CHECK (seniority IN ('senior', 'junior')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE
);

-- Insert Default Users (Password: 'admin123' - hash to be generated in app)
-- Note: In production, use real hashes. These are placeholders.
-- You will need to use the Python helper to generate real hashes.
