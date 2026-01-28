# AI-SOC Watchdog Testing Guide

This guide explains how to properly test the AI analysis capabilities.

---

## ⚠️ The Problem with Naive Testing

**Bad Test (Biased):**
```
Alert Name: "Mimikatz Credential Dumping Detected"
```
The AI just reads the name and knows it's malicious. This tests nothing!

**Good Test (Blind):**
```
Alert Name: "Process Execution Detected"
Process Logs: rundll32.exe comsvcs.dll MiniDump 624 lsass.dmp
```
The AI must analyze the actual evidence to determine it's credential theft.

---

## Test Scripts

### 1. Comprehensive Blind Test (RECOMMENDED)
```bash
python scripts/test_comprehensive_blind.py --all
```

Tests:
- **False Positives** - Benign activities that look suspicious
- **True Positives** - Real attacks with forensic evidence
- **Edge Cases** - Ambiguous scenarios
- **Volume** - Mixed alerts under load

All alerts have **neutral names**. AI must analyze:
- Process command lines
- Network connections
- File operations
- Parent process chains

### 2. Blind Test with Logs
```bash
python scripts/test_blind_with_logs.py --all
```

Creates alerts with full forensic log chains:
- Process logs (what ran, parent process, command line)
- Network logs (connections, bytes, protocols)
- File logs (created, modified, deleted files)

### 3. Check Results
```bash
# Wait 2-3 minutes for AI analysis, then:
python scripts/test_comprehensive_blind.py --check
```

---

## Test Scenarios

### Benign Scenarios (Should be BENIGN)

| Scenario | Evidence | Why Benign |
|----------|----------|------------|
| Windows Update | svchost.exe → wuauserv, Microsoft IPs | Legitimate Windows service |
| Chrome Update | GoogleUpdate.exe, Google IPs | Known software updater |
| IT Admin RDP | mstsc.exe from IT subnet, business hours | Normal IT support |
| Antivirus Scan | MsMpEng.exe reading files | Windows Defender activity |
| Backup Job | VeeamAgent.exe, large data to backup server | Scheduled backup |
| Software Install | msiexec.exe from Program Files | Legitimate installation |

### Malicious Scenarios (Should be MALICIOUS)

| Scenario | Evidence | Why Malicious |
|----------|----------|---------------|
| PowerShell Cradle | Encoded PS, download from Tor IP | Known attack technique |
| LSASS Dump | rundll32 comsvcs.dll MiniDump lsass.dmp | Credential theft |
| Data Exfiltration | curl POST 100MB to unknown IP at 3AM | Data theft |
| Ransomware | .locked files, README_DECRYPT.txt | Encryption attack |
| Lateral Movement | PsExec/WMI to other internal hosts | Network spread |
| Reverse Shell | PowerShell TCPClient to external IP:4444 | C2 connection |
| DNS Tunneling | High volume encoded DNS queries | Data exfil via DNS |

### Edge Cases (Should be SUSPICIOUS)

| Scenario | Evidence | Why Ambiguous |
|----------|----------|---------------|
| Admin PsExec | IT admin using PsExec legitimately | Tool is dual-use |
| Encoded PS from CI/CD | Jenkins running encoded PowerShell | Could be build script |

---

## Running Tests

### Prerequisites
```bash
# Start the backend
python app.py

# In another terminal, run tests
```

### Quick Test (5 minutes)
```bash
# Create 10 benign + 10 malicious scenarios
python scripts/test_blind_with_logs.py --all

# Wait 2-3 minutes, then check
python scripts/test_blind_with_logs.py --check
```

### Full Test Suite (15 minutes)
```bash
# Run all test types
python scripts/test_comprehensive_blind.py --all

# This creates:
# - 10 false positive scenarios
# - 10 true positive scenarios  
# - 2 edge cases
# - 30 volume test alerts

# Check results
python scripts/test_comprehensive_blind.py --check
```

### Volume/Stress Test
```bash
# 100 random alerts
python scripts/test_comprehensive_blind.py --volume 100
```

---

## Expected Results

### Good AI Performance
- Benign scenarios → BENIGN verdict (90%+ confidence)
- Malicious scenarios → MALICIOUS verdict (80%+ confidence)
- Edge cases → SUSPICIOUS verdict (investigating required)
- Low false positive rate (<10%)
- Low false negative rate (<5% for obvious attacks)

### What to Look For

**False Positive (Bad):**
```
Alert: Windows Update activity
Expected: BENIGN
AI Verdict: MALICIOUS ❌
```

**False Negative (Very Bad):**
```
Alert: Ransomware encrypting files
Expected: MALICIOUS
AI Verdict: BENIGN ❌
```

**Correct Analysis (Good):**
```
Alert: Process Execution Detected
Evidence: powershell.exe -enc ... downloading from Tor IP
Expected: MALICIOUS
AI Verdict: MALICIOUS ✓
Confidence: 95%
```

---

## Legacy Tests (Deprecated)

These old tests have **biased alert names** that give away the answer:

```bash
# ⚠️ DON'T USE FOR REAL TESTING
python scripts/test_volume_and_benign.py  # Biased names!
```

The alert names like "Mimikatz Credential Dumping" tell the AI the answer.

---

## Metrics to Track

1. **Accuracy** - % of correct verdicts
2. **False Positive Rate** - Benign marked as malicious
3. **False Negative Rate** - Malicious marked as benign
4. **Processing Time** - Seconds per alert
5. **Confidence Calibration** - Are high-confidence verdicts correct?

---

## Troubleshooting

### Alerts Stuck in "Analyzing"
- Check backend logs for errors
- Verify Anthropic API key is valid
- Check if budget is exhausted

### All Alerts Getting Same Verdict
- Check if logs are being inserted correctly
- Verify RAG system is providing context
- Check AI prompt construction

### High False Positive Rate
- Review benign scenarios
- Check if certain patterns are being over-weighted
- Tune detection thresholds

---

*Last updated: January 2026*
