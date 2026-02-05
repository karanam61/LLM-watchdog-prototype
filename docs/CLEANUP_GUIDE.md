# Codebase Cleanup Guide

## Files to Move from Root Directory

### Move to scripts/debug/
```
debug_python.py
diagnose_auth.py
diagnose_hash_mismatch.py
```

### Move to scripts/testing/
```
ai_transparency_proof.py
comprehensive_test.py
smoking_gun_test.py
test_alert_flow.py
test_debug_api.py
verify_ai_facts.py
verify_auth_completeness.py
verify_connection.py
```

### Move to scripts/maintenance/
```
clear_analysis_fixed.py
clear_analysis.py
clear_error_alerts.py
clear_rule_based.py
reset_budget.py
clean_all_unicode.py
fix_unicode_app.py
fix_unicode.py
```

### Move to scripts/utilities/
```
analyze_alert_status.py
check_api.py
check_rag_data.py
check_schema.py
expose_ai_reasoning.py
generate_20_realistic_alerts.py
generate_infrastructure_alerts.py
inspect_existing_data.py
new_endpoint.py
preflight_check.py
show_deep_analysis_alerts.py
visualize_rag_comprehensive.py
visualize_rag_usage.py
```

### Keep in Root
```
app.py
requirements.txt
.env
README.md
```

### Can Be Deleted
```
app_utf8.py              - Likely duplicate of app.py
master_launch.py         - If not used
API_key claude.txt       - Should be in .env
AWSkey.txt               - Should be in .env
backend_status.log       - Generated file
verification_report.txt  - Generated file
```

### SQL Files - Move to backend/storage/migrations/
```
add_chain_of_thought_column.sql
fix_hash_column.sql
```

## Ideal Structure After Cleanup

```
AI Project/
├── app.py
├── requirements.txt
├── .env
├── README.md
├── architecture.png
├── backend/
│   ├── ai/
│   ├── core/
│   ├── monitoring/
│   ├── security/
│   ├── storage/
│   │   └── migrations/
│   └── visualizer/
├── soc-dashboard/
├── docs/
├── tests/
├── scripts/
│   ├── windows/
│   ├── data/
│   ├── debug/
│   ├── testing/
│   ├── maintenance/
│   └── utilities/
└── terraform-s3/
```

## Cleanup Commands (PowerShell)

```powershell
# Create directories
New-Item -ItemType Directory -Path "scripts/debug" -Force
New-Item -ItemType Directory -Path "scripts/testing" -Force
New-Item -ItemType Directory -Path "scripts/maintenance" -Force
New-Item -ItemType Directory -Path "scripts/utilities" -Force
New-Item -ItemType Directory -Path "backend/storage/migrations" -Force

# Move files as needed using Move-Item
```

## Before Deleting

Review these first:
1. master_launch.py - Check if it's used as an alternative launcher
2. app_utf8.py - Compare with app.py, delete if identical
3. API_key claude.txt / AWSkey.txt - Ensure keys are in .env first

After moving files, update any import paths that reference them.
