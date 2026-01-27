import sys
import os
from pathlib import Path

# Add root to path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(PROJECT_ROOT))

from backend.core.parser import parse_splunk_alert
from backend.core.mitre_mapping import map_to_mitre

def verify_core():
    log_dir = PROJECT_ROOT / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "core_verify.txt"
    
    with open(log_file, "w", encoding="utf-8") as f:
        f.write("=== BACKEND CORE POLISH VERIFICATION ===\n")
        
        # 1. PARSER TEST
        f.write("\n[1] Testing Parser...\n")
        try:
            sample = {"search_name": "Test Alert", "severity": "high", "result": {"src_ip": "1.2.3.4"}}
            parsed = parse_splunk_alert(sample)
            if parsed['source_ip'] == "1.2.3.4":
                f.write("   [PASS] Splunk Format Parsing\n")
            else:
                f.write(f"   [FAIL] Splunk Format Parsed: {parsed}\n")
                
            flat = {"alert_name": "Flat", "severity": "low", "src_ip": "5.6.7.8"}
            parsed_flat = parse_splunk_alert(flat)
            if parsed_flat['source_ip'] == "5.6.7.8":
                f.write("   [PASS] Flat Format Parsing\n")
            else:
                 f.write(f"   [FAIL] Flat Format Parsing: {parsed_flat}\n")
                 
        except Exception as e:
            f.write(f"   [CRASH] Parser failed: {e}\n")

        # 2. MITRE TEST
        f.write("\n[2] Testing MITRE Mapping...\n")
        try:
            alert = {"alert_name": "Ransomware Detected", "description": "Files encrypted"}
            tid = map_to_mitre(alert)
            if tid == "T1486":
                f.write("   [PASS] Ransomware -> T1486\n")
            else:
                f.write(f"   [FAIL] Expected T1486, got {tid}\n")
                
            # Test robustness (None input)
            safe_check = map_to_mitre({})
            if safe_check is None:
                f.write("   [PASS] Empty Input Handled Safely\n")
            else:
                f.write(f"   [FAIL] Empty Input returned {safe_check}\n")

        except Exception as e:
            f.write(f"   [CRASH] MITRE Mapping failed: {e}\n")

if __name__ == "__main__":
    verify_core()
    print("Verification complete. Check logs/core_verify.txt")
