-- Add chain_of_thought column to alerts table for step-by-step AI reasoning

ALTER TABLE alerts 
ADD COLUMN IF NOT EXISTS ai_chain_of_thought JSONB DEFAULT '[]'::jsonb;

COMMENT ON COLUMN alerts.ai_chain_of_thought IS 'Step-by-step reasoning process from AI analysis. Each step has observation, analysis, and conclusion.';
