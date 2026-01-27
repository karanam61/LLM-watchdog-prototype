"""
Tokenize Company Infrastructure
================================
This script tokenizes all sensitive infrastructure data and stores mappings in Supabase.

What it does:
1. Loads company_infrastructure.json (with REAL data)
2. Tokenizes all IPs, hostnames, usernames, emails
3. Stores token mappings in Supabase token_mapping table
4. Creates company_infrastructure_tokenized.json for ChromaDB
5. Preserves all metadata (roles, criticality, etc.)

Run this ONCE before generating alerts.
"""

import sys
import os
import json
from pathlib import Path

# Add backend directory to path so we can import tokenizer
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

from security.tokenizer import tokenizer


def tokenize_infrastructure():
    """
    Main function to tokenize company infrastructure.
    """
    print("=" * 60)
    print("INFRASTRUCTURE TOKENIZATION")
    print("=" * 60)
    
    # Load company infrastructure JSON
    infrastructure_path = os.path.join(str(backend_dir), "core", "sample_data", "company_infrastructure.json")
    
    if not os.path.exists(infrastructure_path):
        print(f"[ERROR] ERROR: File not found: {infrastructure_path}")
        print(f"Backend dir: {backend_dir}")
        print(f"Current working directory: {os.getcwd()}")
        print("Please ensure company_infrastructure.json exists in backend/core/sample_data/")
        return
    
    print(f"[OK] Loading infrastructure from: {infrastructure_path}")
    
    with open(infrastructure_path, 'r') as f:
        infrastructure = json.load(f)
    
    # Create tokenized version (deep copy structure)
    tokenized = {
        "_comment": "TOKENIZED VERSION - Safe to share with AI/ChromaDB",
        "_documentation": infrastructure.get("_documentation", {}),
        "company_info": infrastructure.get("company_info", {}),
        "network_topology": infrastructure.get("network_topology", {}),
        "employees": [],
        "servers": [],
        "external_threats": infrastructure.get("external_threats", {}),
        "business_context": infrastructure.get("business_context", {})
    }
    
    # Statistics
    stats = {
        "employees_processed": 0,
        "servers_processed": 0,
        "ips_tokenized": 0,
        "hostnames_tokenized": 0,
        "usernames_tokenized": 0,
        "emails_tokenized": 0
    }
    
    print("\n" + "=" * 60)
    print("TOKENIZING EMPLOYEES")
    print("=" * 60)
    
    # Tokenize employees
    for employee in infrastructure.get("employees", []):
        print(f"\nProcessing: {employee['real_name']}")
        
        tokenized_employee = {
            "tokenized_name": tokenizer.tokenize('username', employee['real_name']),
            "tokenized_email": tokenizer.tokenize('email', employee['real_email']),
            "tokenized_ip": tokenizer.tokenize('ip', employee['real_ip']),
            "tokenized_hostname": tokenizer.tokenize('hostname', employee['real_hostname']),
            "metadata": employee['metadata']  # Keep metadata as-is
        }
        
        print(f"  Real Name: {employee['real_name']} -> {tokenized_employee['tokenized_name']}")
        print(f"  Real Email: {employee['real_email']} -> {tokenized_employee['tokenized_email']}")
        print(f"  Real IP: {employee['real_ip']} -> {tokenized_employee['tokenized_ip']}")
        print(f"  Real Hostname: {employee['real_hostname']} -> {tokenized_employee['tokenized_hostname']}")
        print(f"  Department: {employee['metadata']['department']}")
        print(f"  Role: {employee['metadata']['role']}")
        
        tokenized["employees"].append(tokenized_employee)
        
        stats["employees_processed"] += 1
        stats["usernames_tokenized"] += 1
        stats["emails_tokenized"] += 1
        stats["ips_tokenized"] += 1
        stats["hostnames_tokenized"] += 1
    
    print("\n" + "=" * 60)
    print("TOKENIZING SERVERS")
    print("=" * 60)
    
    # Tokenize servers
    for server in infrastructure.get("servers", []):
        print(f"\nProcessing: {server['real_hostname']}")
        
        tokenized_server = {
            "tokenized_hostname": tokenizer.tokenize('hostname', server['real_hostname']),
            "tokenized_ip": tokenizer.tokenize('ip', server['real_ip']),
            "metadata": server['metadata']  # Keep metadata as-is
        }
        
        print(f"  Real Hostname: {server['real_hostname']} -> {tokenized_server['tokenized_hostname']}")
        print(f"  Real IP: {server['real_ip']} -> {tokenized_server['tokenized_ip']}")
        print(f"  Server Type: {server['metadata']['server_type']}")
        print(f"  Criticality: {server['metadata']['criticality']}")
        
        tokenized["servers"].append(tokenized_server)
        
        stats["servers_processed"] += 1
        stats["ips_tokenized"] += 1
        stats["hostnames_tokenized"] += 1
    
    # Save tokenized version
    output_path = os.path.join(str(backend_dir), "core", "sample_data", "company_infrastructure_tokenized.json")
    
    print("\n" + "=" * 60)
    print("SAVING TOKENIZED DATA")
    print("=" * 60)
    
    with open(output_path, 'w') as f:
        json.dump(tokenized, f, indent=2)
    
    print(f"[OK] Saved tokenized infrastructure to: {output_path}")
    
    # Print summary
    print("\n" + "=" * 60)
    print("TOKENIZATION SUMMARY")
    print("=" * 60)
    print(f"Employees processed: {stats['employees_processed']}")
    print(f"Servers processed: {stats['servers_processed']}")
    print(f"Total IPs tokenized: {stats['ips_tokenized']}")
    print(f"Total Hostnames tokenized: {stats['hostnames_tokenized']}")
    print(f"Total Usernames tokenized: {stats['usernames_tokenized']}")
    print(f"Total Emails tokenized: {stats['emails_tokenized']}")
    print(f"\nAll tokens stored in Supabase 'token_mapping' table")
    print(f"Tokenized file ready for ChromaDB ingestion")
    
    print("\n" + "=" * 60)
    print("[OK] TOKENIZATION COMPLETE")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Verify tokens in Supabase token_mapping table")
    print("2. Use tokenized infrastructure to generate alerts")
    print("3. Ingest tokenized data to ChromaDB")


if __name__ == "__main__":
    try:
        tokenize_infrastructure()
    except Exception as e:
        print(f"\n[ERROR] ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)