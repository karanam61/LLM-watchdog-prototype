-- Run this in your Supabase SQL Editor
-- (Removed the 'status' column addition since it already exists)

ALTER TABLE alerts ADD COLUMN ai_verdict TEXT;
ALTER TABLE alerts ADD COLUMN ai_confidence FLOAT;
ALTER TABLE alerts ADD COLUMN ai_evidence JSONB;
ALTER TABLE alerts ADD COLUMN ai_reasoning TEXT;
ALTER TABLE alerts ADD COLUMN ai_recommendation TEXT;
-- Setting default for existing status column if needed, otherwise ignore:
-- ALTER TABLE alerts ALTER COLUMN status SET DEFAULT 'pending_ai_analysis';

ALTER TABLE alerts ADD COLUMN analyst_verdict TEXT;
ALTER TABLE alerts ADD COLUMN analyst_notes TEXT;
