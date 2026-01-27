"""
ChromaDB Knowledge Base Ingestion
==================================
Ingests all knowledge sources into ChromaDB for RAG-powered alert analysis.

What it ingests:
1. Attack patterns (attack_patterns_2025.json)
2. Detection rules (detection_rules.json)
3. Detection signatures (detection_signatures.json)
4. Historical alert analyses (historical_alert_analyses.json)
5. Business rules (business_rules.json)
6. MITRE severity (mitre_severity.json)
7. Company infrastructure (company_infrastructure_tokenized.json)

Collections created:
- attack_patterns: Attack techniques and IOCs
- detection_rules: YARA/Sigma rules
- detection_signatures: Signature patterns
- historical_analyses: Past alert analyses with outcomes
- business_rules: Organizational context and priorities
- mitre_severity: Technique severity and business impact
- company_infrastructure: Organizational assets and context

Usage:
    python scripts/ingest_to_chromadb.py
    python scripts/ingest_to_chromadb.py --reset  # Clear and rebuild
"""

import sys
import os
import json
from pathlib import Path
from datetime import datetime

backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

import chromadb
from chromadb.config import Settings
import argparse


def load_json_file(filename):
    """Load JSON file from sample_data directory."""
    path = os.path.join(str(backend_dir), "core", "sample_data", filename)
    
    if not os.path.exists(path):
        print(f"[WARNING]  Warning: {filename} not found at {path}")
        return None
    
    with open(path, 'r') as f:
        return json.load(f)


def setup_chromadb(reset=False):
    """Initialize ChromaDB client with persistent storage."""
    
    persist_dir = os.path.join(str(backend_dir), "chromadb_data")
    
    # Create directory if it doesn't exist
    os.makedirs(persist_dir, exist_ok=True)
    
    print(f"[*] ChromaDB storage: {persist_dir}")
    
    # Initialize client
    client = chromadb.PersistentClient(path=persist_dir)
    
    if reset:
        print("[*]  Resetting ChromaDB (deleting all existing collections)...")
        
        # Delete all existing collections
        collections = client.list_collections()
        for collection in collections:
            client.delete_collection(collection.name)
            print(f"   [OK] Deleted: {collection.name}")
    
    return client


def verify_chromadb():
    """Verify what's currently in ChromaDB."""
    
    print("=" * 60)
    print("CHROMADB VERIFICATION")
    print("=" * 60)
    
    persist_dir = os.path.join(str(backend_dir), "chromadb_data")
    
    if not os.path.exists(persist_dir):
        print(f"[ERROR] ChromaDB directory not found: {persist_dir}")
        print("   Run ingestion first: python scripts/ingest_to_chromadb.py")
        return
    
    client = chromadb.PersistentClient(path=persist_dir)
    collections = client.list_collections()
    
    if not collections:
        print("[ERROR] No collections found in ChromaDB")
        print("   Run ingestion first: python scripts/ingest_to_chromadb.py")
        return
    
    print(f"\n[OK] Found {len(collections)} collections:\n")
    
    for collection in collections:
        count = collection.count()
        metadata = collection.metadata
        print(f"[DATA] {collection.name}")
        print(f"   Documents: {count}")
        print(f"   Description: {metadata.get('description', 'N/A')}")
        
        # Show sample
        if count > 0:
            sample = collection.get(limit=1)
            if sample and sample['documents']:
                preview = sample['documents'][0][:150] + "..." if len(sample['documents'][0]) > 150 else sample['documents'][0]
                print(f"   Sample: {preview}")
        print()
    
    print("=" * 60)


def dry_run_summary(data_files):
    """Show what would be ingested without actually doing it."""
    
    print("=" * 60)
    print("DRY RUN - PREVIEW")
    print("=" * 60)
    
    total_items = 0
    
    for name, data in data_files.items():
        if data is None:
            print(f"[ERROR] {name}: File not found")
            continue
        
        count = 0
        
        if name == "attack_patterns":
            print(f"\n[CHECK] DEBUG {name}:")
            print(f"   Type: {type(data)}")
            print(f"   Top-level keys: {list(data.keys())[:5] if isinstance(data, dict) else 'Not a dict'}")
            
            attack_categories = data.get('attack_categories', {})
            print(f"   'attack_categories' exists: {('attack_categories' in data)}")
            print(f"   Categories found: {list(attack_categories.keys()) if isinstance(attack_categories, dict) else 'None'}")
            
            for category, category_data in attack_categories.items():
                if isinstance(category_data, dict):
                    patterns = category_data.get('patterns', [])
                    if isinstance(patterns, list):
                        print(f"   Category '{category}': {len(patterns)} patterns")
                        count += len(patterns)
        
        elif name == "detection_rules":
            print(f"\n[CHECK] DEBUG {name}:")
            print(f"   Type: {type(data)}")
            print(f"   Top-level keys: {list(data.keys())[:10] if isinstance(data, dict) else 'Not a dict'}")
            
            # Count non-metadata keys as rules
            for key in data.keys():
                if not key.startswith('_') and isinstance(data[key], dict):
                    count += 1
                    print(f"   Rule '{key}': Found")
        
        elif name == "detection_signatures":
            print(f"\n[CHECK] DEBUG {name}:")
            print(f"   Type: {type(data)}")
            print(f"   Categories: {list(data.keys())[:10] if isinstance(data, dict) else 'Not a dict'}")
            
            for category, sig_data in data.items():
                if not category.startswith('_') and isinstance(sig_data, dict):
                    cat_count = 0
                    if 'regex_patterns' in sig_data:
                        cat_count += len(sig_data['regex_patterns'])
                    if 'behavioral' in sig_data:
                        cat_count += len(sig_data['behavioral'])
                    if 'suricata_rules' in sig_data:
                        cat_count += len(sig_data['suricata_rules']) if isinstance(sig_data['suricata_rules'], list) else 0
                    
                    print(f"   Category '{category}': {cat_count} signatures")
                    count += cat_count
        
        elif name == "historical_analyses":
            count = len(data.get('historical_analyses', []))
        
        elif name == "business_rules":
            count += len(data.get('department_priority', {}))
            count += len(data.get('known_false_positive_patterns', []))
            count += len(data.get('automatic_escalation_criteria', []))
        
        elif name == "mitre_severity":
            count = len(data.get('techniques', {}))
        
        elif name == "company_infrastructure":
            count = len(data.get('employees', [])) + len(data.get('servers', []))
        
        print(f"[OK] {name}: {count} items")
        total_items += count
    
    print(f"\n[STATS] Total items to ingest: {total_items}")
    print("=" * 60)
    print("\nTo actually ingest, run without --dry-run flag")
    print("To reset and rebuild: python scripts/ingest_to_chromadb.py --reset")
    print("=" * 60)


def ingest_attack_patterns(client, data):
    """Ingest attack patterns with metadata."""
    
    if not data:
        print("[WARNING]  Skipping attack patterns (file not found)")
        return
    
    print("\n[CONTEXT] Ingesting Attack Patterns...")
    
    # Create or get collection
    collection = client.get_or_create_collection(
        name="attack_patterns",
        metadata={"description": "Attack techniques and patterns"}
    )
    
    documents = []
    metadatas = []
    ids = []
    
    count = 0
    
    # Handle nested structure: attack_categories -> category -> patterns
    attack_categories = data.get('attack_categories', {})
    
    for category, category_data in attack_categories.items():
        if not isinstance(category_data, dict):
            continue
        
        patterns = category_data.get('patterns', [])
        
        if not isinstance(patterns, list):
            continue
        
        for pattern in patterns:
            # Create searchable text
            doc_text = f"""
Attack Pattern: {pattern.get('name', 'Unknown')}
Category: {category}
MITRE Technique: {pattern.get('technique', 'N/A')}
Command: {pattern.get('command', '')}
Why Malicious: {pattern.get('why_malicious', '')}
Indicators: {', '.join(pattern.get('indicators', []))}
Detection: {category_data.get('detection_difficulty', 'unknown')}
Sophistication: {category_data.get('sophistication', 'unknown')}
"""
            
            documents.append(doc_text.strip())
            metadatas.append({
                "name": pattern.get('name', 'Unknown'),
                "category": category,
                "mitre_technique": pattern.get('technique', 'N/A'),
                "sophistication": category_data.get('sophistication', 'unknown'),
                "type": "attack_pattern"
            })
            ids.append(f"attack_{category}_{count}")
            count += 1
    
    if documents:
        collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )
        print(f"   [OK] Ingested {len(documents)} attack patterns")
    else:
        print("   [WARNING]  No attack patterns found")


def ingest_detection_rules(client, data):
    """Ingest detection rules."""
    
    if not data:
        print("[WARNING]  Skipping detection rules (file not found)")
        return
    
    print("\n[CHECK] Ingesting Detection Rules...")
    
    collection = client.get_or_create_collection(
        name="detection_rules",
        metadata={"description": "YARA, Sigma, and custom detection rules"}
    )
    
    documents = []
    metadatas = []
    ids = []
    
    # File structure: each top-level key is a rule (except _documentation)
    for rule_id, rule in data.items():
        if rule_id.startswith('_') or not isinstance(rule, dict):
            continue  # Skip metadata
        
        # Extract rule information
        name = rule.get('name', rule_id)
        severity = rule.get('severity', 'unknown')
        mitre = rule.get('mitre', 'N/A')
        
        # Build searchable text from all available fields
        doc_parts = [f"Detection Rule: {name}"]
        
        if 'splunk_query' in rule:
            splunk = rule['splunk_query']
            doc_parts.append(f"SPL Query: {splunk.get('spl', '')}")
            doc_parts.append(f"Explanation: {splunk.get('explanation', '')}")
        
        if 'suricata_rule' in rule:
            suricata = rule['suricata_rule']
            doc_parts.append(f"Suricata Rule: {suricata.get('rule', '')}")
        
        if 'zeek_script' in rule:
            zeek = rule['zeek_script']
            doc_parts.append(f"Zeek Script: {zeek.get('script', '')}")
        
        if 'raw_logs_analyzed' in rule:
            logs = rule['raw_logs_analyzed']
            doc_parts.append(f"Log Source: {logs.get('source', 'N/A')}")
        
        if 'alert_output' in rule:
            alert = rule['alert_output']
            doc_parts.append(f"Alert: {alert.get('alert_name', '')}")
            doc_parts.append(f"Description: {alert.get('description', '')}")
        
        doc_text = "\n".join(doc_parts)
        
        documents.append(doc_text.strip())
        metadatas.append({
            "name": name,
            "rule_type": "correlation",
            "severity": severity,
            "mitre_techniques": mitre,
            "type": "detection_rule"
        })
        ids.append(f"rule_{rule_id}")
    
    if documents:
        collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )
        print(f"   [OK] Ingested {len(documents)} detection rules")
    else:
        print("   [WARNING]  No detection rules found")


def ingest_detection_signatures(client, data):
    """Ingest detection signatures."""
    
    if not data:
        print("[WARNING]  Skipping detection signatures (file not found)")
        return
    
    print("\n[TARGET] Ingesting Detection Signatures...")
    
    collection = client.get_or_create_collection(
        name="detection_signatures",
        metadata={"description": "Network and file signatures"}
    )
    
    documents = []
    metadatas = []
    ids = []
    
    # File structure: each top-level key is a signature category
    for sig_category, sig_data in data.items():
        if sig_category.startswith('_') or not isinstance(sig_data, dict):
            continue
        
        # Handle regex_patterns
        if 'regex_patterns' in sig_data:
            for pattern in sig_data['regex_patterns']:
                doc_text = f"""
Signature Category: {sig_category}
Pattern Name: {pattern.get('name', 'Unknown')}
Regex: {pattern.get('pattern', '')}
Confidence: {pattern.get('confidence', 'unknown')}
Type: regex
"""
                documents.append(doc_text.strip())
                metadatas.append({
                    "category": sig_category,
                    "name": pattern.get('name', 'Unknown'),
                    "sig_type": "regex",
                    "confidence": pattern.get('confidence', 'unknown'),
                    "type": "detection_signature"
                })
                ids.append(f"sig_{sig_category}_{pattern.get('name', len(ids))}")
        
        # Handle behavioral patterns
        if 'behavioral' in sig_data:
            for behavior in sig_data['behavioral']:
                doc_text = f"""
Signature Category: {sig_category}
Behavioral Indicator: {behavior.get('name', 'Unknown')}
Indicator: {behavior.get('indicator', behavior.get('pattern', ''))}
Threshold: {behavior.get('threshold', 'N/A')}
Type: behavioral
"""
                documents.append(doc_text.strip())
                metadatas.append({
                    "category": sig_category,
                    "name": behavior.get('name', 'Unknown'),
                    "sig_type": "behavioral",
                    "type": "detection_signature"
                })
                ids.append(f"sig_{sig_category}_behav_{len(ids)}")
        
        # Handle suricata_rules if present
        if 'suricata_rules' in sig_data and isinstance(sig_data['suricata_rules'], list):
            for idx, rule in enumerate(sig_data['suricata_rules']):
                doc_text = f"""
Signature Category: {sig_category}
Suricata Rule: {rule}
Type: suricata
"""
                documents.append(doc_text.strip())
                metadatas.append({
                    "category": sig_category,
                    "sig_type": "suricata",
                    "type": "detection_signature"
                })
                ids.append(f"sig_{sig_category}_suricata_{idx}")
    
    if documents:
        collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )
        print(f"   [OK] Ingested {len(documents)} detection signatures")
    else:
        print("   [WARNING]  No detection signatures found")


def ingest_historical_analyses(client, data):
    """Ingest historical alert analyses (training examples)."""
    
    if not data:
        print("[WARNING]  Skipping historical analyses (file not found)")
        return
    
    print("\n[STATS] Ingesting Historical Alert Analyses...")
    
    collection = client.get_or_create_collection(
        name="historical_analyses",
        metadata={"description": "Past alert analyses with outcomes and lessons"}
    )
    
    documents = []
    metadatas = []
    ids = []
    
    analyses = data.get('historical_analyses', [])
    
    for analysis in analyses:
        doc_text = f"""
Alert: {analysis.get('alert_name', 'Unknown')}
MITRE Technique: {analysis.get('mitre_technique', 'N/A')}
Severity: {analysis.get('severity', 'unknown')}
Department: {analysis.get('department', 'unknown')}

AI Analysis: {analysis.get('ai_analysis', '')}

Analyst Decision: {analysis.get('analyst_decision', 'Unknown')}
Analyst Notes: {analysis.get('analyst_notes', '')}

Actions Taken: {', '.join(analysis.get('actions_taken', []))}

Business Impact: {analysis.get('business_impact', '')}

Lessons Learned: {analysis.get('lessons_learned', '')}

Resolution Time: {analysis.get('resolution_time_minutes', 0)} minutes
False Positive: {analysis.get('false_positive', False)}
"""
        
        documents.append(doc_text.strip())
        metadatas.append({
            "alert_name": analysis.get('alert_name', 'Unknown'),
            "mitre_technique": analysis.get('mitre_technique', 'N/A'),
            "severity": analysis.get('severity', 'unknown'),
            "department": analysis.get('department', 'unknown'),
            "decision": analysis.get('analyst_decision', 'Unknown'),
            "false_positive": str(analysis.get('false_positive', False)),
            "escalated": str(analysis.get('escalated', False)),
            "resolution_time": str(analysis.get('resolution_time_minutes', 0)),
            "type": "historical_analysis"
        })
        ids.append(analysis.get('alert_id', f"hist_{len(ids)}"))
    
    if documents:
        collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )
        print(f"   [OK] Ingested {len(documents)} historical analyses")
        
        # Show breakdown
        true_pos = sum(1 for a in analyses if not a.get('false_positive', False))
        false_pos = len(analyses) - true_pos
        print(f"      - True Positives: {true_pos}")
        print(f"      - False Positives: {false_pos}")
    else:
        print("   [WARNING]  No historical analyses found")


def ingest_business_rules(client, data):
    """Ingest business rules and organizational context."""
    
    if not data:
        print("[WARNING]  Skipping business rules (file not found)")
        return
    
    print("\n[*] Ingesting Business Rules...")
    
    collection = client.get_or_create_collection(
        name="business_rules",
        metadata={"description": "Organizational priorities and context"}
    )
    
    documents = []
    metadatas = []
    ids = []
    
    count = 0
    
    # Department priorities
    dept_priorities = data.get('department_priority', {})
    for dept, info in dept_priorities.items():
        doc_text = f"""
Department: {dept}
Priority Level: {info.get('priority_level', 'unknown')}
Justification: {info.get('justification', '')}
Escalation Threshold: {info.get('escalation_threshold', 'standard')}
Typical Users: {info.get('typical_users', 0)}
High Value Target: {info.get('high_value_targets', False)}
Note: {info.get('note', '')}
"""
        
        documents.append(doc_text.strip())
        metadatas.append({
            "rule_category": "department_priority",
            "department": dept,
            "priority": info.get('priority_level', 'unknown'),
            "type": "business_rule"
        })
        ids.append(f"dept_{dept}")
        count += 1
    
    # False positive patterns
    fp_patterns = data.get('known_false_positive_patterns', [])
    for idx, pattern in enumerate(fp_patterns):
        doc_text = f"""
False Positive Pattern: {pattern.get('pattern', 'Unknown')}
Department: {pattern.get('source_department', 'any')}
Reason: {pattern.get('reason', '')}
Action: {pattern.get('action', 'investigate')}
Historical False Positive Rate: {pattern.get('historical_false_positive_rate', 'unknown')}
Note: {pattern.get('note', '')}
"""
        
        documents.append(doc_text.strip())
        metadatas.append({
            "rule_category": "false_positive_pattern",
            "pattern": pattern.get('pattern', 'Unknown'),
            "department": pattern.get('source_department', 'any'),
            "auto_close": str(pattern.get('auto_close', False)),
            "type": "business_rule"
        })
        ids.append(f"fp_{idx}")
        count += 1
    
    # Escalation criteria
    esc_criteria = data.get('automatic_escalation_criteria', [])
    for idx, criteria in enumerate(esc_criteria):
        doc_text = f"""
Escalation Rule: {criteria.get('condition', 'Unknown')}
Action: {criteria.get('action', 'escalate')}
Notify: {', '.join(criteria.get('notify', []))}
Reason: {criteria.get('reason', '')}
"""
        
        documents.append(doc_text.strip())
        metadatas.append({
            "rule_category": "escalation_criteria",
            "condition": criteria.get('condition', 'Unknown'),
            "action": criteria.get('action', 'escalate'),
            "type": "business_rule"
        })
        ids.append(f"esc_{idx}")
        count += 1
    
    if documents:
        collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )
        print(f"   [OK] Ingested {count} business rules")
    else:
        print("   [WARNING]  No business rules found")


def ingest_mitre_severity(client, data):
    """Ingest MITRE technique severity and business impact."""
    
    if not data:
        print("[WARNING]  Skipping MITRE severity (file not found)")
        return
    
    print("\n[*]  Ingesting MITRE Severity Data...")
    
    collection = client.get_or_create_collection(
        name="mitre_severity",
        metadata={"description": "MITRE ATT&CK technique severity and business impact"}
    )
    
    documents = []
    metadatas = []
    ids = []
    
    techniques = data.get('techniques', {})
    
    for tech_id, tech_info in techniques.items():
        doc_text = f"""
MITRE Technique: {tech_id}
Name: {tech_info.get('technique_name', 'Unknown')}
Tactic: {tech_info.get('tactic', 'unknown')}
Severity: {tech_info.get('severity', 'unknown')}
Average Cost: ${tech_info.get('average_cost_usd', 0):,}
Damage Score: {tech_info.get('damage_score', 0)}/100
Description: {tech_info.get('description', '')}
Why Critical: {tech_info.get('why_critical', '')}
Business Justification: {tech_info.get('business_justification', '')}
"""
        
        documents.append(doc_text.strip())
        metadatas.append({
            "technique_id": tech_id,
            "technique_name": tech_info.get('technique_name', 'Unknown'),
            "tactic": tech_info.get('tactic', 'unknown'),
            "severity": tech_info.get('severity', 'unknown'),
            "average_cost": str(tech_info.get('average_cost_usd', 0)),
            "damage_score": str(tech_info.get('damage_score', 0)),
            "type": "mitre_severity"
        })
        ids.append(f"mitre_{tech_id}")
    
    if documents:
        collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )
        print(f"   [OK] Ingested {len(documents)} MITRE techniques")
    else:
        print("   [WARNING]  No MITRE techniques found")


def ingest_company_infrastructure(client, data):
    """Ingest tokenized company infrastructure."""
    
    if not data:
        print("[WARNING]  Skipping company infrastructure (file not found)")
        return
    
    print("\n[*]  Ingesting Company Infrastructure...")
    
    collection = client.get_or_create_collection(
        name="company_infrastructure",
        metadata={"description": "Organizational assets and context (tokenized)"}
    )
    
    documents = []
    metadatas = []
    ids = []
    
    # Employees
    employees = data.get('employees', [])
    for idx, emp in enumerate(employees):
        doc_text = f"""
Employee: {emp.get('tokenized_name', 'Unknown')}
Department: {emp.get('metadata', {}).get('department', 'unknown')}
Role: {emp.get('metadata', {}).get('role', 'unknown')}
High Value Target: {emp.get('metadata', {}).get('high_value_target', False)}
Access Level: {emp.get('metadata', {}).get('access_level', 'standard')}
Privileged Access: {', '.join(emp.get('metadata', {}).get('privileged_access', []))}
Typical Behavior: {emp.get('metadata', {}).get('typical_behavior', {})}
"""
        
        documents.append(doc_text.strip())
        metadatas.append({
            "entity_type": "employee",
            "tokenized_name": emp.get('tokenized_name', 'Unknown'),
            "department": emp.get('metadata', {}).get('department', 'unknown'),
            "role": emp.get('metadata', {}).get('role', 'unknown'),
            "high_value": str(emp.get('metadata', {}).get('high_value_target', False)),
            "type": "infrastructure"
        })
        ids.append(f"emp_{idx}")
    
    # Servers
    servers = data.get('servers', [])
    for idx, server in enumerate(servers):
        doc_text = f"""
Server: {server.get('tokenized_hostname', 'Unknown')}
Type: {server.get('metadata', {}).get('server_type', 'unknown')}
Operating System: {server.get('metadata', {}).get('os', 'unknown')}
Criticality: {server.get('metadata', {}).get('criticality', 'unknown')}
Contains: {', '.join(server.get('metadata', {}).get('contains', []))}
Compliance: {', '.join(server.get('metadata', {}).get('compliance', []))}
RPO: {server.get('metadata', {}).get('rpo_hours', 0)} hours
RTO: {server.get('metadata', {}).get('rto_hours', 0)} hours
"""
        
        documents.append(doc_text.strip())
        metadatas.append({
            "entity_type": "server",
            "tokenized_hostname": server.get('tokenized_hostname', 'Unknown'),
            "server_type": server.get('metadata', {}).get('server_type', 'unknown'),
            "criticality": server.get('metadata', {}).get('criticality', 'unknown'),
            "type": "infrastructure"
        })
        ids.append(f"server_{idx}")
    
    if documents:
        collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )
        print(f"   [OK] Ingested {len(employees)} employees and {len(servers)} servers")
    else:
        print("   [WARNING]  No infrastructure found")


def main():
    """Main ingestion process."""
    
    parser = argparse.ArgumentParser(description='Ingest knowledge base into ChromaDB')
    parser.add_argument('--reset', action='store_true', help='Reset ChromaDB (delete all collections)')
    parser.add_argument('--dry-run', action='store_true', help='Preview ingestion without writing to ChromaDB')
    parser.add_argument('--verify', action='store_true', help='Verify existing ChromaDB collections')
    args = parser.parse_args()
    
    # Verify mode - just check what's in ChromaDB
    if args.verify:
        verify_chromadb()
        return
    
    print("=" * 60)
    print("CHROMADB KNOWLEDGE BASE INGESTION")
    if args.dry_run:
        print("MODE: DRY RUN (Preview Only)")
    print("=" * 60)
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Load all data files
    print("\n[*] Loading data files...")
    attack_patterns = load_json_file("attack_patterns_2025.json")
    detection_rules = load_json_file("detection_rules.json")
    detection_signatures = load_json_file("detection_signatures.json")
    historical_analyses = load_json_file("historical_alert_analyses.json")
    business_rules = load_json_file("business_rules.json")
    mitre_severity = load_json_file("mitre_severity.json")
    company_infrastructure = load_json_file("company_infrastructure_tokenized.json")
    
    # Dry run mode - just preview
    if args.dry_run:
        data_files = {
            "attack_patterns": attack_patterns,
            "detection_rules": detection_rules,
            "detection_signatures": detection_signatures,
            "historical_analyses": historical_analyses,
            "business_rules": business_rules,
            "mitre_severity": mitre_severity,
            "company_infrastructure": company_infrastructure
        }
        dry_run_summary(data_files)
        return
    
    # Setup ChromaDB
    client = setup_chromadb(reset=args.reset)
    
    # Ingest everything
    ingest_attack_patterns(client, attack_patterns)
    ingest_detection_rules(client, detection_rules)
    ingest_detection_signatures(client, detection_signatures)
    ingest_historical_analyses(client, historical_analyses)
    ingest_business_rules(client, business_rules)
    ingest_mitre_severity(client, mitre_severity)
    ingest_company_infrastructure(client, company_infrastructure)
    
    # Summary
    print("\n" + "=" * 60)
    print("INGESTION COMPLETE")
    print("=" * 60)
    
    collections = client.list_collections()
    print(f"\n[STATS] Total Collections: {len(collections)}")
    for collection in collections:
        count = collection.count()
        print(f"   - {collection.name}: {count} documents")
    
    print(f"\n[OK] Knowledge base ready for RAG queries!")
    print(f"Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[ERROR] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
