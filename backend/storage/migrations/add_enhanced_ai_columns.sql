-- Add enhanced AI analysis columns to alerts table
-- Run this in Supabase SQL Editor

-- Confidence factors breakdown (JSONB)
ALTER TABLE alerts 
ADD COLUMN IF NOT EXISTS ai_confidence_factors JSONB DEFAULT '{}'::jsonb;

COMMENT ON COLUMN alerts.ai_confidence_factors IS 'Breakdown of confidence factors: log_evidence, osint_match, evidence_quality, reasoning_depth (0-100 each)';

-- OSINT threat intelligence data (JSONB)
ALTER TABLE alerts 
ADD COLUMN IF NOT EXISTS ai_osint_data JSONB DEFAULT '{}'::jsonb;

COMMENT ON COLUMN alerts.ai_osint_data IS 'OSINT enrichment data: summary, threat_score, indicators, source_ip_intel, dest_ip_intel';

-- Processing pipeline status (JSONB)
ALTER TABLE alerts 
ADD COLUMN IF NOT EXISTS ai_processing_pipeline JSONB DEFAULT '{}'::jsonb;

COMMENT ON COLUMN alerts.ai_processing_pipeline IS 'Status of each pipeline phase: security_gates, optimization, context, ai_analysis, validation, observability';

-- Model information
ALTER TABLE alerts 
ADD COLUMN IF NOT EXISTS ai_model_used TEXT;

COMMENT ON COLUMN alerts.ai_model_used IS 'Claude model used for analysis (e.g., claude-sonnet-4-20250514, claude-3-haiku)';

-- Processing time in seconds
ALTER TABLE alerts 
ADD COLUMN IF NOT EXISTS ai_processing_time FLOAT DEFAULT 0;

COMMENT ON COLUMN alerts.ai_processing_time IS 'Total processing time in seconds for AI analysis';

-- Cost of API call
ALTER TABLE alerts 
ADD COLUMN IF NOT EXISTS ai_cost FLOAT DEFAULT 0;

COMMENT ON COLUMN alerts.ai_cost IS 'Cost in USD for the Claude API call';

-- Recommendation field (if not exists)
ALTER TABLE alerts 
ADD COLUMN IF NOT EXISTS ai_recommendation TEXT;

COMMENT ON COLUMN alerts.ai_recommendation IS 'AI recommended actions for the analyst';

-- Create index for faster queries on analyzed alerts
CREATE INDEX IF NOT EXISTS idx_alerts_ai_verdict ON alerts(ai_verdict);
CREATE INDEX IF NOT EXISTS idx_alerts_ai_confidence ON alerts(ai_confidence);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
