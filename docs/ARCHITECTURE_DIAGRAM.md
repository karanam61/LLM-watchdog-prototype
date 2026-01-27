# Architecture Diagram - AI-SOC Watchdog

## How to Generate the Diagram

### Option 1: Mermaid (GitHub renders this automatically)
Copy the code below into any `.md` file on GitHub, or use https://mermaid.live

### Option 2: Use https://mermaid.live
1. Go to https://mermaid.live
2. Paste the code below
3. Click "Download PNG" or "Download SVG"

---

## Main System Architecture

```mermaid
flowchart TB
    subgraph SOURCES["🔒 SECURITY DATA SOURCES"]
        SIEM["SIEM Systems<br/>(Splunk, QRadar)"]
        EDR["EDR Tools<br/>(CrowdStrike, Defender)"]
        FW["Firewalls & IDS<br/>(Palo Alto, Snort)"]
    end

    subgraph INGESTION["📥 ALERT INGESTION"]
        WEBHOOK["Webhook Endpoint<br/>/ingest"]
        PARSER["Alert Parser<br/>parser.py"]
        MITRE["MITRE Mapper<br/>mitre_mapping.py"]
        SEVERITY["Severity Classifier<br/>Severity.py"]
    end

    subgraph QUEUE["📋 QUEUE SYSTEM"]
        QM["Queue Manager<br/>Queue_manager.py"]
        PQ["🔴 Priority Queue<br/>CRITICAL/HIGH"]
        SQ["🟡 Standard Queue<br/>MEDIUM/LOW"]
    end

    subgraph CONTEXT["🔍 CONTEXT GATHERING"]
        SUPABASE["Supabase DB<br/>PostgreSQL"]
        LOGS["Forensic Logs<br/>Process | Network | File | Windows"]
        OSINT["OSINT Lookup<br/>osint_lookup.py"]
        RAG["RAG System<br/>rag_system.py"]
        CHROMA["ChromaDB<br/>7 Collections"]
    end

    subgraph AI["🤖 AI ANALYSIS PIPELINE"]
        GUARD_IN["Input Guard<br/>security_guard.py"]
        BUDGET["Budget Tracker<br/>dynamic_budget_tracker.py"]
        CONTEXT_BUILD["Context Builder<br/>alert_analyzer_final.py"]
        CLAUDE["Claude AI<br/>Sonnet / Haiku"]
        GUARD_OUT["Output Guard<br/>security_guard.py"]
        AUTO["Auto-Triage<br/>Benign → Auto-close"]
    end

    subgraph DASHBOARD["📊 REACT DASHBOARD"]
        ANALYST["Analyst Console<br/>Alert Triage"]
        TRANSPARENCY["AI Transparency<br/>Proof & Evidence"]
        RAGVIZ["RAG Visualizer<br/>Knowledge Usage"]
        PERF["Performance<br/>System Metrics"]
        DEBUG["Debug Dashboard<br/>Live Logs"]
    end

    subgraph BACKUP["☁️ FAILOVER"]
        S3["AWS S3<br/>Backup Storage"]
    end

    %% Connections
    SIEM --> WEBHOOK
    EDR --> WEBHOOK
    FW --> WEBHOOK
    
    WEBHOOK --> PARSER
    PARSER --> MITRE
    MITRE --> SEVERITY
    SEVERITY --> QM
    
    QM --> PQ
    QM --> SQ
    
    PQ --> GUARD_IN
    SQ --> GUARD_IN
    
    SUPABASE --> LOGS
    LOGS --> CONTEXT_BUILD
    OSINT --> CONTEXT_BUILD
    RAG --> CHROMA
    CHROMA --> CONTEXT_BUILD
    
    GUARD_IN --> BUDGET
    BUDGET --> CONTEXT_BUILD
    CONTEXT_BUILD --> CLAUDE
    CLAUDE --> GUARD_OUT
    GUARD_OUT --> AUTO
    AUTO --> SUPABASE
    
    SUPABASE --> ANALYST
    SUPABASE --> TRANSPARENCY
    SUPABASE --> RAGVIZ
    SUPABASE --> PERF
    SUPABASE --> DEBUG
    
    SUPABASE -.->|Sync| S3

    %% Styling
    classDef sources fill:#e1f5fe,stroke:#01579b
    classDef ingestion fill:#fff3e0,stroke:#e65100
    classDef queue fill:#fce4ec,stroke:#880e4f
    classDef context fill:#e8f5e9,stroke:#1b5e20
    classDef ai fill:#f3e5f5,stroke:#4a148c
    classDef dashboard fill:#e0f2f1,stroke:#004d40
    classDef backup fill:#eceff1,stroke:#37474f

    class SIEM,EDR,FW sources
    class WEBHOOK,PARSER,MITRE,SEVERITY ingestion
    class QM,PQ,SQ queue
    class SUPABASE,LOGS,OSINT,RAG,CHROMA context
    class GUARD_IN,BUDGET,CONTEXT_BUILD,CLAUDE,GUARD_OUT,AUTO ai
    class ANALYST,TRANSPARENCY,RAGVIZ,PERF,DEBUG dashboard
    class S3 backup
```

---

## AI Analysis Pipeline Detail

```mermaid
flowchart LR
    subgraph PHASE1["Phase 1: Security Gates"]
        A1["Input Validation"]
        A2["Prompt Injection Check"]
        A3["PII Detection"]
    end

    subgraph PHASE2["Phase 2: Optimization"]
        B1["Budget Check"]
        B2["Cache Lookup"]
        B3["Model Selection<br/>Sonnet vs Haiku"]
    end

    subgraph PHASE3["Phase 3: Context"]
        C1["Fetch Forensic Logs"]
        C2["OSINT Enrichment"]
        C3["RAG Knowledge Query"]
    end

    subgraph PHASE4["Phase 4: AI Analysis"]
        D1["Build Prompt"]
        D2["Call Claude API"]
        D3["Parse Response"]
    end

    subgraph PHASE5["Phase 5: Validation"]
        E1["Output Structure Check"]
        E2["Dangerous Command Check"]
        E3["Confidence Validation"]
    end

    subgraph PHASE6["Phase 6: Action"]
        F1["Store in Database"]
        F2["Auto-close if Benign"]
        F3["Log to Audit Trail"]
    end

    PHASE1 --> PHASE2
    PHASE2 --> PHASE3
    PHASE3 --> PHASE4
    PHASE4 --> PHASE5
    PHASE5 --> PHASE6

    style PHASE1 fill:#ffcdd2
    style PHASE2 fill:#fff9c4
    style PHASE3 fill:#c8e6c9
    style PHASE4 fill:#bbdefb
    style PHASE5 fill:#e1bee7
    style PHASE6 fill:#b2dfdb
```

---

## Data Flow Diagram

```mermaid
flowchart TD
    ALERT["🚨 Security Alert"]
    
    ALERT --> PARSE["Parse & Normalize"]
    PARSE --> CLASSIFY["Classify Severity"]
    CLASSIFY --> ROUTE{"Route by Risk Score"}
    
    ROUTE -->|"Risk ≥ 75"| PRIORITY["Priority Queue"]
    ROUTE -->|"Risk < 75"| STANDARD["Standard Queue"]
    
    PRIORITY --> GATHER["Gather Evidence"]
    STANDARD --> GATHER
    
    GATHER --> DB[(Supabase)]
    GATHER --> OSINT["OSINT APIs"]
    GATHER --> KNOWLEDGE[(ChromaDB)]
    
    DB --> BUILD["Build Context"]
    OSINT --> BUILD
    KNOWLEDGE --> BUILD
    
    BUILD --> CLAUDE["🤖 Claude AI"]
    
    CLAUDE --> VERDICT{"Verdict?"}
    
    VERDICT -->|"Malicious"| CRITICAL["🔴 Show to Analyst"]
    VERDICT -->|"Suspicious"| REVIEW["🟡 Review Required"]
    VERDICT -->|"Benign + High Conf"| AUTO["🟢 Auto-Close"]
    
    CRITICAL --> DASHBOARD["📊 Dashboard"]
    REVIEW --> DASHBOARD
    AUTO --> HISTORY["📁 History"]
    
    style ALERT fill:#ff5722,color:#fff
    style CLAUDE fill:#9c27b0,color:#fff
    style CRITICAL fill:#f44336,color:#fff
    style REVIEW fill:#ff9800,color:#fff
    style AUTO fill:#4caf50,color:#fff
```

---

## RAG Knowledge Collections

```mermaid
graph LR
    subgraph RAG["ChromaDB RAG System"]
        M["mitre_severity<br/>201 techniques"]
        H["historical_analyses<br/>Past alerts"]
        B["business_rules<br/>Org policies"]
        A["attack_patterns<br/>IOCs & TTPs"]
        D["detection_rules<br/>SIEM rules"]
        S["detection_signatures<br/>Regex patterns"]
        I["company_infrastructure<br/>Asset context"]
    end

    ALERT["Alert"] --> QUERY["Semantic Query"]
    QUERY --> M
    QUERY --> H
    QUERY --> B
    QUERY --> A
    QUERY --> D
    QUERY --> S
    QUERY --> I
    
    M --> CONTEXT["Combined Context"]
    H --> CONTEXT
    B --> CONTEXT
    A --> CONTEXT
    D --> CONTEXT
    S --> CONTEXT
    I --> CONTEXT
    
    CONTEXT --> CLAUDE["Claude AI"]

    style RAG fill:#e3f2fd
    style CLAUDE fill:#9c27b0,color:#fff
```

---

## Quick Copy-Paste for mermaid.live

Go to https://mermaid.live and paste this simplified version:

```
flowchart TB
    SIEM["🔒 SIEM/EDR"] --> INGEST["📥 Ingestion API"]
    INGEST --> PARSE["Parser + MITRE Mapper"]
    PARSE --> QUEUE["📋 Queue Manager"]
    
    QUEUE --> PQ["🔴 Priority Queue"]
    QUEUE --> SQ["🟡 Standard Queue"]
    
    PQ --> AI["🤖 AI Pipeline"]
    SQ --> AI
    
    DB[(Supabase)] --> AI
    RAG[(ChromaDB RAG)] --> AI
    OSINT["🌐 OSINT"] --> AI
    
    AI --> CLAUDE["Claude AI<br/>Sonnet/Haiku"]
    CLAUDE --> VERDICT{"Verdict"}
    
    VERDICT --> MAL["🔴 Malicious"]
    VERDICT --> SUS["🟡 Suspicious"]  
    VERDICT --> BEN["🟢 Benign"]
    
    MAL --> DASH["📊 Dashboard"]
    SUS --> DASH
    BEN --> AUTO["Auto-Close"]
    
    DASH --> ANALYST["Analyst Console"]
    DASH --> TRANS["AI Transparency"]
    DASH --> PERF["Performance"]
    
    DB -.-> S3["☁️ S3 Backup"]
```

---

## PlantUML Version (Alternative)

If you prefer PlantUML, use https://www.plantuml.com/plantuml/uml/

```plantuml
@startuml
!theme cerulean

title AI-SOC Watchdog Architecture

package "Data Sources" {
  [SIEM] as siem
  [EDR] as edr
  [Firewall] as fw
}

package "Backend (Flask)" {
  [Parser] as parser
  [MITRE Mapper] as mitre
  [Queue Manager] as queue
}

package "AI Pipeline" {
  [Security Guards] as guard
  [Context Builder] as context
  [Claude AI] as claude
}

database "Supabase" as db
database "ChromaDB" as rag
cloud "OSINT APIs" as osint
cloud "AWS S3" as s3

package "React Dashboard" {
  [Analyst Console] as analyst
  [AI Transparency] as trans
  [Performance] as perf
}

siem --> parser
edr --> parser
fw --> parser

parser --> mitre
mitre --> queue
queue --> guard
guard --> context

db --> context
rag --> context
osint --> context

context --> claude
claude --> db

db --> analyst
db --> trans
db --> perf

db ..> s3 : backup

@enduml
```
