"""
Export MITRE Severity Table from Supabase to JSON
==================================================
Automates the export of mitre_severity table for RAG ingestion.

What it does:
1. Connects to Supabase
2. Fetches all rows from mitre_severity table
3. Converts to JSON format
4. Saves to backend/core/sample_data/mitre_severity.json

Run this whenever MITRE table is updated.
"""

import sys
import os
import json
from pathlib import Path

backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

from dotenv import load_dotenv
load_dotenv()

from supabase import create_client

# Supabase connection
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)


def export_mitre_severity():
    """Export MITRE severity table to JSON."""
    
    print("=" * 60)
    print("MITRE SEVERITY TABLE EXPORT")
    print("=" * 60)
    
    print("\n[STATS] Fetching data from Supabase...")
    
    try:
        # Fetch all rows from mitre_severity table
        result = supabase.table('mitre_severity').select('*').execute()
        
        if not result.data:
            print("[ERROR] No data found in mitre_severity table!")
            return
        
        print(f"[OK] Fetched {len(result.data)} MITRE techniques")
        
        # Convert to structured format
        mitre_data = {
            "_documentation": {
                "purpose": "MITRE ATT&CK technique severity with business impact context",
                "source": "Exported from Supabase mitre_severity table",
                "export_date": "auto-generated",
                "total_techniques": len(result.data)
            },
            "techniques": {}
        }
        
        # Process each row
        for row in result.data:
            technique_id = row.get('technique_id')
            
            mitre_data['techniques'][technique_id] = {
                "technique_id": technique_id,
                "technique_name": row.get('technique_name'),
                "tactic": row.get('tactic'),
                "severity": row.get('severity'),
                "average_cost_usd": row.get('average_cost_usd'),
                "damage_score": row.get('damage_score'),
                "description": row.get('description', ''),
            }
            
            print(f"  [OK] {technique_id}: {row.get('technique_name')}")
        
        # Save to file
        output_path = os.path.join(str(backend_dir), "core", "sample_data", "mitre_severity.json")
        
        with open(output_path, 'w') as f:
            json.dump(mitre_data, f, indent=2)
        
        print("\n" + "=" * 60)
        print("EXPORT COMPLETE")
        print("=" * 60)
        print(f"[OK] Exported {len(result.data)} techniques")
        print(f"[*] Saved to: {output_path}")
        
        # Show summary
        severities = {}
        for tech in mitre_data['techniques'].values():
            sev = tech['severity']
            severities[sev] = severities.get(sev, 0) + 1
        
        print("\n[STATS] Severity Breakdown:")
        for severity, count in sorted(severities.items()):
            print(f"   {severity}: {count} techniques")
        
    except Exception as e:
        print(f"\n[ERROR] ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    export_mitre_severity()