# Codebase Cleanup Guide

## Files to Move from Root Directory

The root directory contains many utility/debug scripts that should be organized. Here's the recommended cleanup:

### Move to `scripts/debug/`
These are debugging utilities:
```
debug_python.py
diagnose_auth.py
diagnose_hash_mismatch.py
```

### Move to `scripts/testing/`
These are test/verification scripts:
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

### Move to `scripts/maintenance/`
These are cleanup/maintenance scripts:
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

### Move to `scripts/utilities/`
These are utility scripts:
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

### Keep in Root (Essential)
```
app.py                    # Main entry point
requirements.txt          # Dependencies
.env                      # Environment variables
README.md                 # Project readme
```

### Can Be Deleted (Duplicates/Obsolete)
```
app_utf8.py              # Likely duplicate of app.py
master_launch.py         # If not used
API_key claude.txt       # Should be in .env, not plain text
AWSkey.txt               # Should be in .env, not plain text
backend_status.log       # Generated file
verification_report.txt  # Generated file
```

### SQL Files → Move to `backend/storage/migrations/`
```
add_chain_of_thought_column.sql
fix_hash_column.sql
```

### Architecture Diagram → Keep
```
architecture.png         # Keep, reference in docs
```

---

## After Cleanup - Ideal Structure

```
AI Project/
├── app.py
├── requirements.txt
├── .env
├── README.md
├── architecture.png
│
├── backend/
│   ├── ai/
│   ├── core/
│   ├── monitoring/
│   ├── scripts/          # Already exists with utilities
│   ├── security/
│   ├── storage/
│   │   └── migrations/   # SQL files
│   └── visualizer/
│
├── soc-dashboard/
│
├── docs/
│
├── tests/
│
├── scripts/
│   ├── windows/          # Startup scripts
│   ├── data/             # Data generation
│   ├── debug/            # Debug utilities
│   ├── testing/          # Test scripts
│   ├── maintenance/      # Cleanup scripts
│   └── utilities/        # General utilities
│
└── terraform-s3/
```

---

## Cleanup Commands (Windows PowerShell)

```powershell
# Create new directories
New-Item -ItemType Directory -Path "scripts/debug" -Force
New-Item -ItemType Directory -Path "scripts/testing" -Force
New-Item -ItemType Directory -Path "scripts/maintenance" -Force
New-Item -ItemType Directory -Path "scripts/utilities" -Force
New-Item -ItemType Directory -Path "backend/storage/migrations" -Force

# Move debug scripts
Move-Item "debug_python.py" "scripts/debug/"
Move-Item "diagnose_auth.py" "scripts/debug/"
Move-Item "diagnose_hash_mismatch.py" "scripts/debug/"

# Move testing scripts
Move-Item "ai_transparency_proof.py" "scripts/testing/"
Move-Item "comprehensive_test.py" "scripts/testing/"
Move-Item "smoking_gun_test.py" "scripts/testing/"
Move-Item "test_alert_flow.py" "scripts/testing/"
Move-Item "test_debug_api.py" "scripts/testing/"
Move-Item "verify_ai_facts.py" "scripts/testing/"
Move-Item "verify_auth_completeness.py" "scripts/testing/"
Move-Item "verify_connection.py" "scripts/testing/"

# Move maintenance scripts
Move-Item "clear_analysis_fixed.py" "scripts/maintenance/"
Move-Item "clear_analysis.py" "scripts/maintenance/"
Move-Item "clear_error_alerts.py" "scripts/maintenance/"
Move-Item "clear_rule_based.py" "scripts/maintenance/"
Move-Item "reset_budget.py" "scripts/maintenance/"
Move-Item "clean_all_unicode.py" "scripts/maintenance/"
Move-Item "fix_unicode_app.py" "scripts/maintenance/"
Move-Item "fix_unicode.py" "scripts/maintenance/"

# Move utility scripts
Move-Item "analyze_alert_status.py" "scripts/utilities/"
Move-Item "check_api.py" "scripts/utilities/"
Move-Item "check_rag_data.py" "scripts/utilities/"
Move-Item "check_schema.py" "scripts/utilities/"
Move-Item "expose_ai_reasoning.py" "scripts/utilities/"
Move-Item "generate_20_realistic_alerts.py" "scripts/utilities/"
Move-Item "generate_infrastructure_alerts.py" "scripts/utilities/"
Move-Item "inspect_existing_data.py" "scripts/utilities/"
Move-Item "new_endpoint.py" "scripts/utilities/"
Move-Item "preflight_check.py" "scripts/utilities/"
Move-Item "show_deep_analysis_alerts.py" "scripts/utilities/"
Move-Item "visualize_rag_comprehensive.py" "scripts/utilities/"
Move-Item "visualize_rag_usage.py" "scripts/utilities/"

# Move SQL files
Move-Item "add_chain_of_thought_column.sql" "backend/storage/migrations/"
Move-Item "fix_hash_column.sql" "backend/storage/migrations/"

# Delete sensitive files (backup first!)
Remove-Item "API_key claude.txt"
Remove-Item "AWSkey.txt"

# Delete generated files
Remove-Item "backend_status.log"
Remove-Item "verification_report.txt"

# Delete potential duplicate
Remove-Item "app_utf8.py"
```

---

## Before Deleting - Check These Files

Review before deleting:
1. `master_launch.py` - Check if it's used as an alternative launcher
2. `app_utf8.py` - Compare with app.py, delete if identical
3. `API_key claude.txt` / `AWSkey.txt` - Ensure keys are in .env first!

---

## Note

After moving files, update any import paths that reference these scripts. Most of these are standalone utilities that don't need import updates.
