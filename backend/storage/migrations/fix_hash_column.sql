-- FIX SCRIPT: Increase password_hash column size
-- Run this in your Supabase SQL Editor

ALTER TABLE users ALTER COLUMN password_hash TYPE TEXT;

-- Verify the change (Output should say 'text')
SELECT column_name, data_type, character_maximum_length
FROM information_schema.columns
WHERE table_name = 'users' AND column_name = 'password_hash';
