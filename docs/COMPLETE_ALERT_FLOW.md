# Complete Alert Flow - Every Single Detail

This document traces EVERY operation from the moment an HTTP request hits the server until the result appears on the dashboard.

---

## STAGE 1: HTTP Request Arrives at `/ingest`

### 1.1 Flask Receives Request
```
Location: app.py line 1277
```

```python
@app.route('/ingest', methods=['POST'])
def ingest_log():
```

**What happens:**
- Flask's WSGI server receives HTTP POST request
- `MAX_CONTENT_LENGTH = 2MB` checked automatically by Flask (line 119)
- If payload > 2MB → returns `413 Payload Too Large`

### 1.2 First Log Entry
```
Location: app.py lines 1281-1290
```

```python
live_logger.log(
    'API',
    'POST /ingest - Alert Received',
    {
        'source_ip': request.remote_addr,
        'content_type': request.content_type,
        '_explanation': 'This is the entry point for all alerts...'
    },
    status='success'
)
```

**Variables assigned:**
- `request.remote_addr` → source IP of sender
- `request.content_type` → should be `application/json`

### 1.3 API Key Validation (Optional)
```
Location: app.py lines 1298-1322
```

```python
ingest_api_key = os.getenv("INGEST_API_KEY")  # Get from .env
if ingest_api_key:
    provided_key = request.headers.get('X-Ingest-Key', '')  # Get from header
    if not secrets.compare_digest(provided_key, ingest_api_key):  # Timing-safe compare
        # LOG FAILURE
        live_logger.log('SECURITY', 'Ingest API Key Validation FAILED', {...})
        return jsonify({"error": "Unauthorized"}), 401  # REJECT
    
    # LOG SUCCESS
    live_logger.log('SECURITY', 'Ingest API Key Validated', {...})
```

**Key points:**
- Uses `secrets.compare_digest()` → prevents timing attacks
- If `INGEST_API_KEY` not set in `.env` → this check is SKIPPED

### 1.4 Extract JSON Body
```
Location: app.py line 1325
```

```python
data = request.json
```

**Variable assigned:**
- `data` → raw JSON dict from HTTP body

---

## STAGE 2: Parse Alert (`parse_splunk_alert`)

### 2.1 Call Parser
```
Location: app.py line 1348
```

```python
parsed = parse_splunk_alert(data)
```

### 2.2 Parser Logic
```
Location: backend/core/parser.py lines 40-90
```

**Print statement:**
```python
print(f"      [INNER TRACE] Parser received keys: {list(alert_data.keys())}")
```

**Two format handlers:**

**Format A: Splunk nested format**
```python
if 'result' in alert_data:
    result_block = alert_data.get('result', {})
    parsed = {
        'alert_name': alert_data.get('search_name', 'Unknown Alert'),
        'severity': alert_data.get('severity', 'medium'),
        'source_ip': result_block.get('src_ip') or result_block.get('source_ip'),
        'dest_ip': result_block.get('dest_ip') or result_block.get('dst_ip'),
        'hostname': result_block.get('hostname') or result_block.get('host'),
        'username': result_block.get('username') or result_block.get('user'),
        'timestamp': result_block.get('_time'),
        'description': result_block.get('signature') or result_block.get('description')
    }
```

**Format B: Flat format**
```python
else:
    parsed = {
        'alert_name': alert_data.get('alert_name') or alert_data.get('search_name') or 'Unknown Alert',
        'severity': alert_data.get('severity', 'medium'),
        'source_ip': alert_data.get('source_ip') or alert_data.get('src_ip'),
        'dest_ip': alert_data.get('dest_ip') or alert_data.get('dst_ip'),
        'hostname': alert_data.get('hostname') or alert_data.get('host'),
        'username': alert_data.get('username') or alert_data.get('user'),
        'timestamp': alert_data.get('timestamp') or alert_data.get('_time'),
        'description': alert_data.get('description') or alert_data.get('signature')
    }
```

**Print statement:**
```python
print(f"      [INNER TRACE] Parser normalized: '{parsed.get('alert_name')}' | IP: {parsed.get('source_ip')}")
```

### 2.3 Tracker Log
```
Location: app.py lines 1349-1356
```

```python
tracker.log_step(
    file_name="backend/core/parser.py", 
    function="parse_splunk_alert",
    purpose="Normalize Splunk format",
    input_data=data,
    objects_created={"parsed": parsed},
    timing_ms=2
)
```

---

## STAGE 3: MITRE Mapping (`map_to_mitre`)

### 3.1 Live Logger Entry
```
Location: app.py lines 1358-1366
```

```python
live_logger.log(
    'FUNCTION',
    'map_to_mitre() - ATT&CK Technique Mapping',
    {
        'alert_name': parsed.get('alert_name'),
        '_explanation': 'map_to_mitre() maps the alert to MITRE ATT&CK techniques using RAG search...'
    },
    status='success'
)
```

### 3.2 Call MITRE Mapper
```
Location: app.py line 1368
```

```python
mitre_technique = map_to_mitre(parsed, tracker=tracker)
```

### 3.3 Inject into Parsed Dict
```
Location: app.py line 1369
```

```python
parsed['mitre_technique'] = mitre_technique
```

### 3.4 Result Log
```
Location: app.py lines 1381-1390
```

```python
live_logger.log(
    'FUNCTION',
    'MITRE Technique Mapped',
    {
        'technique': mitre_technique or 'None detected',
        'alert_name': parsed.get('alert_name'),
        '_explanation': f"Alert mapped to MITRE ATT&CK technique: {mitre_technique or 'No direct mapping found'}"
    },
    status='success' if mitre_technique else 'warning'
)
```

---

## STAGE 4: Severity Classification (`classify_severity`)

### 4.1 Pre-Call Log
```
Location: app.py lines 1392-1401
```

### 4.2 Call Classifier
```
Location: app.py line 1403
```

```python
severity_class = classify_severity(parsed)
```

### 4.3 Classifier Logic
```
Location: backend/core/Severity.py lines 31-43
```

```python
def classify_severity(parsed_alert):
    severity = parsed_alert.get('severity', '').lower()
    
    if severity in ['critical', 'high']:
        return 'CRITICAL_HIGH'
    elif severity in ['medium', 'low']:
        return 'MEDIUM_LOW'
    else:
        return 'MEDIUM_LOW'  # default
```

### 4.4 Result Log
```
Location: app.py lines 1413-1422
```

```python
live_logger.log(
    'FUNCTION',
    'Severity Classified',
    {
        'severity_class': severity_class,
        'queue_target': 'PRIORITY' if severity_class == 'CRITICAL_HIGH' else 'STANDARD',
        '_explanation': f"Alert classified as {severity_class}..."
    },
    status='success'
)
```

---

## STAGE 5: Store in Database (`store_alert`)

### 5.1 Pre-Store Log
```
Location: app.py lines 1434-1444
```

### 5.2 Call Store Function
```
Location: app.py line 1446
```

```python
db_result = store_alert(parsed, mitre_technique, severity_class)
```

### 5.3 Database Insert
```
Location: backend/storage/database.py lines 136-169
```

```python
def store_alert(parsed_alert, mitre_technique, severity_class):
    data = {
        'alert_name': parsed_alert.get('alert_name'),
        'severity': parsed_alert.get('severity'),
        'source_ip': parsed_alert.get('source_ip'),
        'dest_ip': parsed_alert.get('dest_ip'),
        'timestamp': parsed_alert.get('timestamp'),
        'description': parsed_alert.get('description'),
        'mitre_technique': mitre_technique,
        'severity_class': severity_class
    }
    
    try:
        response = supabase.table('alerts').insert(data).execute()
        alert_id = response.data[0]['id']
        
        print(f"      [INNER TRACE] DB Insert Success: ID {alert_id} | Name: {parsed_alert.get('alert_name')}")
        
        # Also sync to S3 for backup
        if S3_FAILOVER_AVAILABLE and alert_id:
            data['id'] = alert_id
            get_s3_failover().sync_single_record('alerts', data)
        
        return response
    except Exception as e:
        # Fallback to S3
        ...
```

### 5.4 Extract Alert ID
```
Location: app.py lines 1449-1453
```

```python
alert_id = None
if db_result and hasattr(db_result, 'data') and db_result.data:
    alert_id = db_result.data[0]['id']
elif db_result and isinstance(db_result, list) and len(db_result) > 0:
    alert_id = db_result[0]['id']
```

### 5.5 Inject ID Back into Parsed
```
Location: app.py lines 1489-1491
```

```python
parsed['id'] = alert_id
parsed['alert_id'] = alert_id  # Redundancy for safety
```

---

## STAGE 6: Queue Routing (`route_alert`)

### 6.1 Pre-Route Log
```
Location: app.py lines 1493-1503
```

### 6.2 Call Queue Manager
```
Location: app.py line 1505
```

```python
qm.route_alert(parsed, severity_class, tracker=tracker)
```

### 6.3 Queue Manager Logic
```
Location: backend/core/Queue_manager.py lines 61-133
```

**Risk calculation:**
```python
mitre = alert.get('mitre_technique')
risk_score = 50  # Default

if mitre:
    risk_result = calculate_risk_score(mitre, severity_class)
    risk_score = risk_result['risk_score']
    damage_score = risk_result['damage_score']
    multiplier = risk_result['severity_multiplier']
else:
    # Fallback severity scores
    severity_scores = {
        'CRITICAL_HIGH': 100,
        'CRITICAL_MEDIUM': 85,
        'HIGH': 70,
        'MEDIUM': 50,
        'LOW': 30
    }
    risk_score = severity_scores.get(severity_class, 50)
```

**Add metadata:**
```python
alert['risk_score'] = risk_score
alert['severity_class'] = severity_class
```

**Thread-safe routing:**
```python
with self.lock:
    if risk_score >= PRIORITY_QUEUE_THRESHOLD:  # Default 75
        print(f"[QUEUE TRACE] [*] Routing to PRIORITY Queue (Risk: {risk_score:.1f})")
        alert['queue_type'] = 'priority'
        self.priority_queue.append(alert)
    else:
        print(f"[QUEUE TRACE] [INGEST] Routing to STANDARD Queue (Risk: {risk_score:.1f})")
        alert['queue_type'] = 'standard'
        self.standard_queue.append(alert)
```

### 6.4 Post-Route Log
```
Location: app.py lines 1507-1516
```

---

## STAGE 7: HTTP Response Returns

```
Location: app.py lines 1590-1596
```

```python
return jsonify({
    "status": "processed", 
    "alert_id": alert_id,
    "mitre_technique": mitre_technique,
    "severity": severity_class,
    "ai_analysis": {}  # Empty - AI runs async
}), 200
```

**AT THIS POINT:**
- HTTP request is COMPLETE (returns to SIEM/caller)
- Alert is sitting in queue (priority or standard)
- Background worker will pick it up

---

## STAGE 8: Background Worker Picks Up Alert

### 8.1 Worker Loop
```
Location: app.py lines 810-850
```

**Print and log:**
```python
print("\n[PRIORITY] Auto-processing PRIORITY queue item...")

live_logger.log(
    'QUEUE',
    'Alert Dequeued from Priority Queue',
    {
        'alert_id': alert.get('alert_id'),
        'alert_name': alert.get('alert_name'),
        'queue': 'priority',
        '_explanation': f"Priority alert dequeued! Alert will now go through the full AI analysis pipeline..."
    }
)
```

### 8.2 Dequeue Alert
```
Location: app.py line 823 / backend/core/Queue_manager.py lines 135-160
```

```python
alert = qm.get_next_alert()
```

**Queue Manager prints:**
```python
print(f"[*] Retrieved from PRIORITY queue")
print(f"   Alert: {alert.get('alert_name', 'Unknown')}")
print(f"   Risk score: {alert.get('risk_score', 0):.1f}")
print(f"   Remaining in priority: {len(self.priority_queue)}")
```

### 8.3 Start AI Tracer
```
Location: app.py lines 852-857
```

```python
ai_tracer.start_operation(
    "Alert Analysis",
    f"Analyzing alert: {alert.get('alert_name', 'Unknown')}",
    expected_duration=25
)
```

### 8.4 Log Pipeline Start
```
Location: app.py lines 859-876
```

```python
live_logger.log(
    'AI',
    'analyzer.analyze_alert() - Starting 26-Feature AI Pipeline',
    {
        'alert_id': alert.get('alert_id'),
        'pipeline_phases': [
            'Phase 1: Security Gates (Features 1-4, 6, 14-17)',
            'Phase 2: Optimization (Features 5, 22)',
            'Phase 3: Context Building (RAG + Forensic Logs)',
            'Phase 4: AI Analysis (Features 9-13 - Claude API)',
            'Phase 5: Output Validation (Features 3-4)',
            'Phase 6: Observability (Features 18-21)'
        ],
        '_explanation': 'Starting the complete AI analysis pipeline...'
    }
)
```

---

## STAGE 9: AI Analysis Pipeline (`analyze_alert`)

### 9.1 Initialize
```
Location: backend/ai/alert_analyzer_final.py lines 155-186
```

```python
start_time = datetime.now()
print("\n" + "="*50)
print(f"[AI TRACE] [GUARD] Analyzer Pipeline START: {alert_dict.get('alert_name', 'Unknown')}")
print("="*50)

tracer.add_step("Pipeline Started", f"Alert: {alert_dict.get('alert_name')}", "success")
```

---

### 9.2 PHASE 1: Security Gates

#### 9.2.1 Input Guard (Features 1-4)
```
Location: backend/ai/alert_analyzer_final.py lines 200-244
```

**Print:**
```python
print("   [AI TRACE] Phase 1: Security Gates (Input Guard)")
```

**Call:**
```python
is_valid, reason, cleaned = self.input_guard.validate(alert)
```

**InputGuard checks (backend/ai/security_guard.py lines 101-196):**
1. Basic validation: `isinstance(alert, dict)`
2. Required fields: `alert.get('alert_name')`, `alert.get('description')`
3. Lakera ML check (DISABLED by default)
4. Regex patterns (11 patterns for prompt injection)
5. Truncate if > 5000 chars
6. Set defaults for optional fields

**If fails:**
```python
if not is_valid:
    print(f"   [AI TRACE] [ERROR] Security Violation: {reason}")
    return self._error("Security violation", reason)
```

#### 9.2.2 Pydantic Validation (Feature 6)
```
Location: backend/ai/alert_analyzer_final.py lines 246-260
```

```python
validated = self.validator.validate_input(cleaned)
```

**Validator (backend/ai/validation.py lines 187-197):**
```python
def validate_input(self, alert: Dict[str, Any]) -> AlertInput:
    validated = AlertInput(**alert)
    print(f"[Validator] [OK] Input validated: {validated.alert_name}")
    return validated
```

#### 9.2.3 Data Protection (Features 14-17)
```
Location: backend/ai/alert_analyzer_final.py lines 262-270
```

```python
validated_dict = validated.dict()
is_safe, reason, protected = self.data_protection.validate_input(validated_dict)
```

**DataProtectionGuard (backend/ai/data_protection.py lines 316-369):**
1. Check tokenization
2. Filter PII (15 patterns: SSN, credit cards, API keys, emails, phones)
3. Check input size (max 10,000 chars)

---

### 9.3 PHASE 2: Optimization

#### 9.3.1 Cache Check (Feature 22)
```
Location: backend/ai/alert_analyzer_final.py lines 296-308
```

```python
if self.cache:
    cache_key = f"alert:{protected.get('alert_id', 'unknown')}"
    cached = self.cache.get(cache_key)
    if cached:
        return json.loads(cached)  # EARLY RETURN - skip AI!
```

#### 9.3.2 Budget Check (Feature 5)
```
Location: backend/ai/alert_analyzer_final.py lines 310-340
```

```python
print("   [AI TRACE] Phase 2: Budget Check")
can_process, cost, reason = self.budget.can_process_queue('priority', 1)

if not can_process:
    print(f"   [AI TRACE] [ERROR] Budget Exhausted: {reason}")
    return self._error("Budget exhausted", reason, queued=True)
```

---

### 9.4 PHASE 3: Context Building

#### 9.4.1 Query Forensic Logs
```
Location: backend/ai/alert_analyzer_final.py lines 357-396
```

```python
target_id = protected_dict.get('id') or protected_dict.get('alert_id')

logs = {
    'process_logs': query_process_logs(target_id),
    'network_logs': query_network_logs(target_id),
    'file_logs': query_file_activity_logs(target_id),
    'windows_logs': query_windows_event_logs(target_id)
}
```

**Each query prints (database.py):**
```python
print(f"      [INNER TRACE] DB Query (Process): AlertID={alert_id} -> Found {count} logs")
```

#### 9.4.2 OSINT Enrichment
```
Location: backend/ai/alert_analyzer_final.py lines 398-425
```

```python
osint_data = enrich_with_osint(protected_dict)
```

Queries:
- IP reputation
- Hash reputation  
- Domain reputation

#### 9.4.3 RAG Context Building
```
Location: backend/ai/alert_analyzer_final.py lines 427-463
```

```python
print("   [AI TRACE] Phase 3: Building RAG Context")
context = self._build_context(protected_dict, logs, osint_data)
print(f"   [AI TRACE] Context Built: {len(context)} chars")
```

**RAG queries 7 ChromaDB collections:**
1. mitre_techniques
2. historical_alerts
3. business_rules
4. attack_patterns
5. detection_rules
6. detection_signatures
7. company_infrastructure

---

### 9.5 PHASE 4: AI Analysis

#### 9.5.1 Claude API Call
```
Location: backend/ai/alert_analyzer_final.py lines 500-513
```

```python
api_start_time = _time.time()

alert_severity = protected_dict.get('severity_class') or protected_dict.get('severity', 'medium')

api_response = self.api_client.analyze_with_resilience(
    context=context,
    budget_tracker=self.budget,
    max_retries=self.max_retries,
    timeout=self.api_timeout,
    estimated_cost=cost,
    severity=alert_severity
)

api_duration = _time.time() - api_start_time
```

**Model selection:**
- `CRITICAL_HIGH` → Claude Sonnet (~$0.02/alert)
- `MEDIUM_LOW` → Claude Haiku (~$0.002/alert)

#### 9.5.2 Log API Metrics
```
Location: backend/ai/alert_analyzer_final.py lines 551-560
```

```python
monitor.log_api_call(
    model=self.api_client.model,
    tokens_in=tokens.get('input', 0),
    tokens_out=tokens.get('output', 0),
    cost=actual_cost,
    duration=api_duration
)
```

#### 9.5.3 Parse Response
```
Location: backend/ai/alert_analyzer_final.py lines 570-584
```

```python
analysis = self._parse_response(api_response['response'])
```

**Parser (lines 734-804):**
1. Extract text from Anthropic response object
2. Find JSON in markdown code blocks OR raw `{...}` 
3. Sanitize control characters
4. Parse JSON
5. Normalize to standard fields: `verdict`, `confidence`, `evidence`, `chain_of_thought`, `reasoning`, `recommendation`

---

### 9.6 PHASE 5: Output Validation

```
Location: backend/ai/alert_analyzer_final.py lines 598-623
```

```python
is_safe, issues = self.output_guard.validate(analysis)

if not is_safe:
    return self._fallback(protected)
```

**OutputGuard (backend/ai/security_guard.py lines 269-338):**
1. Check required fields: `verdict`, `confidence`, `reasoning`
2. Valid verdict: `['malicious', 'benign', 'suspicious', 'error']`
3. Valid confidence: `0.0 <= conf <= 1.0`
4. Scan for dangerous commands (15 patterns: `rm -rf`, `DROP DATABASE`, etc.)
5. Contradiction detection (benign + attack keywords = issue)

---

### 9.7 PHASE 6: Observability

```
Location: backend/ai/alert_analyzer_final.py lines 653-727
```

#### 9.7.1 Build Final Response
```python
duration = (datetime.now() - start_time).total_seconds()
result = {
    'success': True,
    'verdict': analysis.get('verdict', 'suspicious'),
    'confidence': analysis.get('confidence', 0.5),
    'evidence': analysis.get('evidence', []),
    'chain_of_thought': analysis.get('chain_of_thought', []),
    'reasoning': analysis.get('reasoning', ''),
    'recommendation': analysis.get('recommendation', ''),
    'metadata': {
        'alert_id': protected_dict.get('alert_id'),
        'processing_time': duration,
        'cost': api_response.get('cost', 0),
        'timestamp': datetime.now().isoformat()
    }
}
```

#### 9.7.2 Cache Result
```python
if self.cache:
    cache_key = f"alert:{protected_dict.get('alert_id', 'unknown')}"
    self.cache.set(cache_key, json.dumps(result), ex=3600)  # 1 hour TTL
```

#### 9.7.3 Log to Audit/Metrics
```python
self.audit.log_analysis(protected_dict, result, result['metadata'])
self.metrics.record_processing_time(protected_dict.get('alert_id'), duration, 'priority')
self.health.record_api_call(True, duration)
```

#### 9.7.4 Final Print
```python
print(f"[AI TRACE] [OK] Pipeline Complete. Verdict: {result.get('verdict')}")
print("="*50 + "\n")
```

---

## STAGE 10: Update Database with AI Result

```
Location: app.py line 882
```

```python
update_alert_with_ai_analysis(alert['alert_id'], ai_result)
```

**Database update (backend/storage/database.py):**
```python
supabase.table('alerts').update({
    'ai_verdict': result.get('verdict'),
    'ai_confidence': result.get('confidence'),
    'ai_evidence': result.get('evidence'),
    'ai_reasoning': result.get('reasoning'),
    'ai_recommendation': result.get('recommendation'),
    'ai_chain_of_thought': result.get('chain_of_thought'),
    'status': 'analyzed',
    'analyzed_at': datetime.now().isoformat()
}).eq('id', alert_id).execute()
```

---

## STAGE 11: Auto-Close Logic

```
Location: app.py lines 884-911
```

```python
verdict = ai_result.get('verdict', '').lower()
confidence = ai_result.get('confidence', 0)
severity_class = alert.get('severity_class', 'MEDIUM_LOW')

if verdict == 'benign' and confidence >= 0.7 and severity_class != 'CRITICAL_HIGH':
    supabase.table('alerts').update({
        'status': 'closed',
        'auto_closed': True,
        'auto_close_reason': f'AI verdict: benign ({confidence:.0%} confidence)'
    }).eq('id', alert['alert_id']).execute()
    
    print(f"[AUTO-CLOSE] Alert {alert['alert_id']} auto-closed (benign, {confidence:.0%})")
```

---

## STAGE 12: Final Logs

```
Location: app.py lines 914-945
```

```python
monitor.log_alert_processed(
    alert['alert_id'],
    ai_result.get('verdict', 'unknown'),
    ai_result.get('confidence', 0),
    duration,
    ai_result.get('metadata', {}).get('cost', 0)
)

ai_tracer.end_operation(
    success=True,
    result_summary=f"Verdict: {ai_result.get('verdict')} ({ai_result.get('confidence'):.0%})"
)

print(f"[OK] Background Analysis Complete: {alert['alert_id']}")

live_logger.log(
    'AI',
    'AI Analysis Complete - Verdict Determined',
    {
        'alert_id': alert.get('alert_id'),
        'verdict': ai_result.get('verdict'),
        'confidence': f"{ai_result.get('confidence', 0)*100:.0f}%",
        'processing_time': f"{duration:.2f}s",
        '_explanation': f"AI verdict: {ai_result.get('verdict').upper()}..."
    },
    status='success',
    duration=duration
)
```

---

## STAGE 13: Dashboard Fetches Updated Data

### 13.1 Frontend Polls `/alerts`
```
Location: app.py lines 1607-1649
```

```python
@app.route('/alerts', methods=['GET'])
def get_alerts():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    query = supabase.table('alerts').select('*', count='exact')
    response = query.order('created_at', desc=True).range(offset, offset + per_page - 1).execute()
    
    return jsonify({
        "alerts": alerts,
        "count": len(alerts),
        "total": total_count,
        ...
    })
```

### 13.2 Dashboard Displays
The React dashboard (`soc-dashboard/src/pages/AnalystDashboard.jsx`) displays:
- Alert name
- Severity
- AI Verdict (BENIGN/SUSPICIOUS/MALICIOUS)
- Confidence percentage
- Status (open/closed/investigating)
- Evidence list
- Chain of thought reasoning

---

## Summary: Complete Variable Flow

```
HTTP POST → data (raw JSON)
         → parsed (normalized dict)
         → mitre_technique (string)
         → severity_class (CRITICAL_HIGH/MEDIUM_LOW)
         → db_result → alert_id (UUID)
         → parsed['id'] = alert_id (injected)
         → qm.route_alert() → queue (priority/standard)
         → [HTTP RETURNS 200]
         
Worker picks up → alert (from queue)
               → cleaned (after InputGuard)
               → validated (Pydantic model)
               → protected (after DataProtection)
               → logs (4 log types from DB)
               → osint_data (threat intel)
               → context (RAG + logs + OSINT string)
               → api_response (Claude response)
               → analysis (parsed JSON)
               → result (final dict)
               → [DB UPDATE]
               → [DASHBOARD DISPLAYS]
```
