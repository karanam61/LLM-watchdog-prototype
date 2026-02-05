# Complete Alert Flow

This document traces every operation from the moment an HTTP request hits the server until the result appears on the dashboard.

## Stage 1: HTTP Request Arrives at /ingest

### 1.1 Flask Receives Request

```
Location: app.py line 1277
```

```python
@app.route('/ingest', methods=['POST'])
def ingest_log():
```

Flask's WSGI server receives the HTTP POST request. `MAX_CONTENT_LENGTH = 2MB` is enforced automatically (line 119). Payloads exceeding this return `413 Payload Too Large`.

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

Variables assigned:
- `request.remote_addr` - source IP of sender
- `request.content_type` - should be `application/json`

### 1.3 API Key Validation (Optional)

```
Location: app.py lines 1298-1322
```

```python
ingest_api_key = os.getenv("INGEST_API_KEY")
if ingest_api_key:
    provided_key = request.headers.get('X-Ingest-Key', '')
    if not secrets.compare_digest(provided_key, ingest_api_key):
        live_logger.log('SECURITY', 'Ingest API Key Validation FAILED', {...})
        return jsonify({"error": "Unauthorized"}), 401
    
    live_logger.log('SECURITY', 'Ingest API Key Validated', {...})
```

Uses `secrets.compare_digest()` for timing-safe comparison. If `INGEST_API_KEY` is not set in `.env`, this check is skipped entirely.

### 1.4 Extract JSON Body

```
Location: app.py line 1325
```

```python
data = request.json
```

`data` now holds the raw JSON dict from the HTTP body.

## Stage 2: Parse Alert

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

The parser handles two input formats:

Format A - Splunk nested format (has `result` key):

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

Format B - Flat format:

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

## Stage 3: MITRE Mapping

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

## Stage 4: Severity Classification

### 4.1 Call Classifier

```
Location: app.py line 1403
```

```python
severity_class = classify_severity(parsed)
```

### 4.2 Classifier Logic

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

## Stage 5: Database Insert

The parsed alert is inserted into Supabase:

```python
db_result = supabase.table('alerts').insert({
    'alert_name': parsed.get('alert_name'),
    'severity': parsed.get('severity'),
    'severity_class': severity_class,
    'source_ip': parsed.get('source_ip'),
    'dest_ip': parsed.get('dest_ip'),
    'hostname': parsed.get('hostname'),
    'username': parsed.get('username'),
    'description': parsed.get('description'),
    'mitre_technique': parsed.get('mitre_technique'),
    'raw_data': data,
    'status': 'pending'
}).execute()

alert_id = db_result.data[0]['id']
parsed['id'] = alert_id
```

## Stage 6: Queue Routing

### 6.1 Route Alert

```python
queue = qm.route_alert(parsed)
```

### 6.2 Queue Manager Logic

```
Location: backend/core/Queue_manager.py
```

```python
def route_alert(self, alert):
    severity_class = alert.get('severity_class', 'MEDIUM_LOW')
    
    if severity_class == 'CRITICAL_HIGH':
        self.priority_queue.put(alert)
        return 'priority'
    else:
        self.standard_queue.put(alert)
        return 'standard'
```

## Stage 7: HTTP Response Returns

```python
return jsonify({
    "status": "received",
    "alert_id": alert_id,
    "queue": queue,
    "severity_class": severity_class
}), 200
```

At this point the HTTP request is complete. AI analysis happens in the background.

## Stage 8: Background Worker Picks Up Alert

The worker thread continuously polls both queues, prioritizing the priority queue:

```python
def process_alerts():
    while True:
        try:
            alert = qm.priority_queue.get(timeout=0.5)
        except Empty:
            try:
                alert = qm.standard_queue.get(timeout=0.5)
            except Empty:
                continue
        
        analyze_alert(alert)
```

## Stage 9: AI Analysis Pipeline

This is the core AI processing. The analyzer runs through six phases.

### 9.1 Phase 1: Input Sanitization

```
Location: backend/ai/alert_analyzer_final.py lines 381-404
```

```python
cleaned = self.input_guard.sanitize(alert_dict)
```

InputGuard (in `backend/ai/security_guard.py` lines 59-144) performs:

1. JSON decoding protection
2. Unicode normalization (NFKC)
3. Control character removal
4. Field length limits (10KB per field, 500KB total)
5. Prompt injection detection (blocks patterns like `ignore previous`, `system:`, etc.)

### 9.2 Phase 2: Schema Validation

```
Location: backend/ai/alert_analyzer_final.py lines 419-442
```

```python
validated = self.validator.validate(cleaned)
```

Uses Pydantic model `AlertSchema`:

```python
class AlertSchema(BaseModel):
    alert_id: str
    alert_name: str
    severity: str = 'medium'
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    description: Optional[str] = None
    mitre_technique: Optional[str] = None
```

### 9.3 Phase 3: Data Protection

```
Location: backend/ai/alert_analyzer_final.py lines 457-480
```

```python
protected = self.protection.protect(validated)
protected_dict = protected.dict()
```

DataProtection (in `backend/ai/security_guard.py` lines 147-266) handles:

1. IP redaction (internal IPs like 10.x.x.x, 192.168.x.x become `[INTERNAL_IP_xxx]`)
2. Username pseudonymization (becomes `[USER_xxx]` with consistent hashing)
3. Hostname masking
4. Sensitive pattern redaction (SSNs, credit cards, API keys, passwords)

### 9.4 Phase 4: Context Building

```
Location: backend/ai/alert_analyzer_final.py lines 483-520
```

Gathers three types of context:

1. Historical logs from database:
```python
logs = get_related_logs(protected_dict, limit=50)
```

2. RAG search for similar alerts:
```python
rag_context = self.rag.search(protected_dict.get('description', ''), top_k=5)
```

3. OSINT threat intelligence:
```python
osint_data = self.osint.lookup(protected_dict.get('source_ip'))
```

Final context string:
```python
context = f"""
Historical Logs:
{format_logs(logs)}

Similar Past Alerts:
{rag_context}

Threat Intelligence:
{format_osint(osint_data)}
"""
```

### 9.5 Phase 5: Claude API Call

#### 9.5.1 Build Prompt

```
Location: backend/ai/alert_analyzer_final.py lines 523-548
```

```python
prompt = self.prompt_builder.build(protected_dict, context)
```

PromptBuilder creates a structured prompt with:
- System instructions (role, output format, safety rules)
- Alert data (all protected fields)
- Context (logs, RAG, OSINT)
- Output schema (JSON with verdict, confidence, evidence, etc.)

#### 9.5.2 API Call

```python
api_response = self.api_client.call(prompt, max_tokens=2000)
```

Metrics logged:
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

Parser steps:
1. Extract text from Anthropic response object
2. Find JSON in markdown code blocks or raw `{...}`
3. Sanitize control characters
4. Parse JSON
5. Normalize to standard fields: `verdict`, `confidence`, `evidence`, `chain_of_thought`, `reasoning`, `recommendation`

### 9.6 Phase 6: Output Validation

```
Location: backend/ai/alert_analyzer_final.py lines 598-623
```

```python
is_safe, issues = self.output_guard.validate(analysis)

if not is_safe:
    return self._fallback(protected)
```

OutputGuard (in `backend/ai/security_guard.py` lines 269-338) checks:
1. Required fields present: `verdict`, `confidence`, `reasoning`
2. Valid verdict: one of `malicious`, `benign`, `suspicious`, `error`
3. Valid confidence: between 0.0 and 1.0
4. No dangerous commands (scans for 15 patterns like `rm -rf`, `DROP DATABASE`, etc.)
5. No contradictions (e.g., benign verdict with attack keywords)

### 9.7 Phase 7: Observability

```
Location: backend/ai/alert_analyzer_final.py lines 653-727
```

Build final response:

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

Cache result:

```python
if self.cache:
    cache_key = f"alert:{protected_dict.get('alert_id', 'unknown')}"
    self.cache.set(cache_key, json.dumps(result), ex=3600)  # 1 hour TTL
```

Log to audit/metrics:

```python
self.audit.log_analysis(protected_dict, result, result['metadata'])
self.metrics.record_processing_time(protected_dict.get('alert_id'), duration, 'priority')
self.health.record_api_call(True, duration)
```

## Stage 10: Update Database with AI Result

```
Location: app.py line 882
```

```python
update_alert_with_ai_analysis(alert['alert_id'], ai_result)
```

Database update:

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

## Stage 11: Auto-Close Logic

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
```

Auto-close triggers when:
- Verdict is `benign`
- Confidence is at least 70%
- Severity is not `CRITICAL_HIGH`

## Stage 12: Final Logs

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

## Stage 13: Dashboard Fetches Updated Data

### 13.1 Frontend Polls /alerts

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

## Summary: Complete Variable Flow

```
HTTP POST -> data (raw JSON)
          -> parsed (normalized dict)
          -> mitre_technique (string)
          -> severity_class (CRITICAL_HIGH/MEDIUM_LOW)
          -> db_result -> alert_id (UUID)
          -> parsed['id'] = alert_id (injected)
          -> qm.route_alert() -> queue (priority/standard)
          -> [HTTP RETURNS 200]
          
Worker picks up -> alert (from queue)
               -> cleaned (after InputGuard)
               -> validated (Pydantic model)
               -> protected (after DataProtection)
               -> logs (4 log types from DB)
               -> osint_data (threat intel)
               -> context (RAG + logs + OSINT string)
               -> api_response (Claude response)
               -> analysis (parsed JSON)
               -> result (final dict)
               -> [DB UPDATE]
               -> [DASHBOARD DISPLAYS]
```
