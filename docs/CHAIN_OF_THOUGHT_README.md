# Chain of Thought Feature

## What Was Added

### AI Prompt Changes
Updated prompts to request 5-step reasoning from Claude. Each step includes:
- Observation: What the AI saw in logs/alert
- Analysis: Technical interpretation
- Conclusion: How this contributes to the verdict

### Backend Changes

backend/ai/rag_system.py - Added chain of thought to JSON schema:
```json
{
  "chain_of_thought": [
    {"step": 1, "observation": "...", "analysis": "...", "conclusion": "..."}
  ]
}
```

backend/ai/alert_analyzer_final.py - Extracts and passes chain of thought from AI response.

backend/storage/database.py - Stores chain of thought in database.

### Database Migration Required

Run this SQL in Supabase:
```sql
ALTER TABLE alerts 
ADD COLUMN IF NOT EXISTS ai_chain_of_thought JSONB DEFAULT '[]'::jsonb;
```

## How to Apply

1. Go to Supabase Dashboard, SQL Editor
2. Paste the SQL above
3. Run the query
4. Restart backend

## Example Output

```json
{
  "step": 1,
  "observation": "847 files encrypted with .wcry extension",
  "analysis": "WannaCry ransomware signature",
  "conclusion": "Strong indicator of active ransomware infection"
},
{
  "step": 2,  
  "observation": "Shadow copies deleted via vssadmin.exe",
  "analysis": "T1490 Inhibit System Recovery",
  "conclusion": "Attacker eliminating recovery options"
}
```

## Why This Matters

- Transparency: See each logical step
- Trust: Verify the AI reasoning
- Learning: Understand how evidence connects
- Debugging: Identify if AI misinterpreted data
