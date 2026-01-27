
import os
import sys
import json
import chromadb
from pathlib import Path

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

def seed_rag_db():
    print("="*70)
    print("[START] STARTING REAL RAG DATABASE SEEDING (FROM FILES)")
    print("="*70)

    # 1. Setup paths
    backend_dir = Path(__file__).parent.parent
    data_dir = os.path.join(str(backend_dir), "core", "sample_data")
    chromadb_path = os.path.join(str(backend_dir), "chromadb_data")
    
    print(f"[*] Reading Json Data: {data_dir}")
    print(f"[*] Database Path:   {chromadb_path}")
    
    client = chromadb.PersistentClient(path=chromadb_path)
    
    # helper
    def load_json(name):
        path = os.path.join(data_dir, name)
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"  [ERROR] Failed to load {name}: {e}")
            return None

    def seed_collection(name, documents, metadatas, ids):
        try:
            try:
                client.delete_collection(name)
            except:
                pass
            
            collection = client.create_collection(name)
            
            # Batch add to avoid limits
            batch_size = 500
            for i in range(0, len(documents), batch_size):
                collection.add(
                    documents=documents[i:i+batch_size],
                    metadatas=metadatas[i:i+batch_size],
                    ids=ids[i:i+batch_size]
                )
            print(f"  [OK] Seeded '{name}' with {len(documents)} items.")
        except Exception as e:
            print(f"  [ERROR] Failed to seed '{name}': {e}")

    # =========================================================================
    # 1. MITRE SEVERITY
    # =========================================================================
    print("\n[DATA] Processing MITRE Data...")
    mitre_data = load_json("mitre_severity.json")
    if mitre_data:
        docs, metas, ids = [], [], []
        # Support both list and dict formats depending on file version
        techniques = mitre_data.get('techniques', {})
        
        # If dict, iterate values
        items = techniques.values() if isinstance(techniques, dict) else techniques
        
        for t in items:
            # Flatten to string
            content = f"Technique: {t.get('technique_name')} ({t.get('technique_id')}). Severity: {t.get('severity')}. Description: {t.get('description')}."
            docs.append(content)
            metas.append({
                "technique_id": t.get('technique_id', 'unknown'), 
                "severity": t.get('severity', 'unknown')
            })
            ids.append(t.get('technique_id', f"mitre_{len(ids)}"))
            
        seed_collection("mitre_severity", docs, metas, ids)

    # =========================================================================
    # 2. HISTORICAL ANALYSES
    # =========================================================================
    print("\n[DATA] Processing Historical Alerts...")
    hist_data = load_json("historical_alert_analyses.json")
    if hist_data:
        docs, metas, ids = [], [], []
        # JSON structure might be list of alerts
        alerts = hist_data.get('datasets', []) # Or root list
        if isinstance(hist_data, list): alerts = hist_data
        
        for i, h in enumerate(alerts):
            content = f"Past Alert: {h.get('alert_name')}. Verdict: {h.get('verdict')}. Analysis: {h.get('analysis_summary')}."
            docs.append(content)
            metas.append({"verdict": h.get('verdict', 'unknown')})
            ids.append(f"hist_{i}")
            
        seed_collection("historical_analyses", docs, metas, ids)

    # =========================================================================
    # 3. BUSINESS RULES
    # =========================================================================
    print("\n[DATA] Processing Business Rules...")
    rules_data = load_json("business_rules.json")
    if rules_data:
        docs, metas, ids = [], [], []
        
        # Parse departments
        depts = rules_data.get('department_priority', {})
        for dept, info in depts.items():
            content = f"Department '{dept}' Priority: {info.get('priority_level')}. Justification: {info.get('justification')}."
            docs.append(content)
            metas.append({"dept": dept, "type": "priority"})
            ids.append(f"rule_dept_{dept}")
            
        seed_collection("business_rules", docs, metas, ids)

    # =========================================================================
    # 4. ATTACK PATTERNS
    # =========================================================================
    print("\n[DATA] Processing Attack Patterns...")
    patt_data = load_json("attack_patterns_2025.json")
    if patt_data:
        docs, metas, ids = [], [], []
        patterns = patt_data.get('patterns', [])
        
        for i, p in enumerate(patterns):
            content = f"Attack Pattern: {p.get('name')}. Indicators: {p.get('indicators')}. Description: {p.get('description')}."
            docs.append(content)
            metas.append({"type": p.get('category', 'general')})
            ids.append(f"patt_{i}")
            
        seed_collection("attack_patterns", docs, metas, ids)

    # =========================================================================
    # 5. INFRASTRUCTURE (Context)
    # =========================================================================
    print("\n[DATA] Processing Infrastructure...")
    infra_data = load_json("company_infrastructure.json")
    if infra_data:
        docs, metas, ids = [], [], []
        
        # Employees
        employees = infra_data.get('employees', [])
        for i, e in enumerate(employees):
            content = f"Employee: {e.get('name')} (User: {e.get('username')}). Role: {e.get('role')}. Dept: {e.get('department')}."
            docs.append(content)
            metas.append({"entity_type": "employee", "username": e.get('username')})
            ids.append(f"emp_{i}")
            
        # Assets
        assets = infra_data.get('assets', [])
        for i, a in enumerate(assets):
            content = f"Asset: {a.get('hostname')}. Type: {a.get('type')}. Criticality: {a.get('criticality')}."
            docs.append(content)
            metas.append({"entity_type": "server", "hostname": a.get('hostname')})
            ids.append(f"asset_{i}")
            
        seed_collection("company_infrastructure", docs, metas, ids)

    # =========================================================================
    # 6. SIGNATURES & RULES (Quick load)
    # =========================================================================
    print("\n[DATA] Processing Detection Logics...")
    # Just seed placeholders if strict json parsing fails, but try to load
    
    det_data = load_json("detection_rules.json") 
    if det_data:
        docs, metas, ids = [], [], []
        rules = det_data.get('rules', [])
        for i, r in enumerate(rules):
            docs.append(f"Rule: {r.get('name')}. Logic: {r.get('logic')}.")
            metas.append({"id": r.get('id')})
            ids.append(f"dr_{i}")
        seed_collection("detection_rules", docs, metas, ids)

    sig_data = load_json("detection_signatures.json")
    if sig_data:
        docs, metas, ids = [], [], []
        sigs = sig_data.get('signatures', [])
        for i, s in enumerate(sigs):
            docs.append(f"Signature: {s.get('pattern')}. Type: {s.get('type')}.")
            metas.append({"type": s.get('type')})
            ids.append(f"sig_{i}")
        seed_collection("detection_signatures", docs, metas, ids)


    print("\n" + "="*70)
    print("[OK] REAL DATA SEEDING COMPLETE")
    print("="*70)

if __name__ == "__main__":
    seed_rag_db()
