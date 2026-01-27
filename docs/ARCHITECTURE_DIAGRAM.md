# Architecture Diagram - AI-SOC Watchdog

## How to Generate the Diagram

1. Go to **https://mermaid.live**
2. Delete everything in the code panel
3. Paste one of the diagrams below
4. Click **Actions** (top right) → **Download PNG**

---

## RECOMMENDED: Clean Linear Diagram (Copy This)

```mermaid
flowchart LR
    %% Layer 1: Input
    A[SIEM / EDR / Firewall] --> B[Webhook API]
    
    %% Layer 2: Processing  
    B --> C[Parser]
    C --> D[MITRE Mapper]
    D --> E[Severity Classifier]
    
    %% Layer 3: Queue
    E --> F{Queue Manager}
    F --> G[Priority Queue]
    F --> H[Standard Queue]
    
    %% Layer 4: AI Pipeline
    G --> I[Security Guard]
    H --> I
    I --> J[Context Builder]
    
    %% Context Sources
    K[(Supabase DB)] --> J
    L[(ChromaDB RAG)] --> J
    M[OSINT APIs] --> J
    
    %% Layer 5: AI
    J --> N[Claude AI]
    
    %% Layer 6: Output
    N --> O{Verdict}
    O --> P[Malicious]
    O --> Q[Suspicious]
    O --> R[Benign]
    
    %% Layer 7: Actions
    P --> S[Dashboard]
    Q --> S
    R --> T[Auto-Close]
    
    %% Backup
    K -.-> U[S3 Backup]
```

---

## Alternative: Vertical Flow (Top to Bottom)

```mermaid
flowchart TD
    A[Security Tools] --> B[Ingestion API]
    B --> C[Parser + MITRE]
    C --> D[Queue Manager]
    
    D --> E[Priority]
    D --> F[Standard]
    
    E --> G[AI Pipeline]
    F --> G
    
    H[(Database)] --> G
    I[(RAG)] --> G
    J[OSINT] --> G
    
    G --> K[Claude AI]
    K --> L{Decision}
    
    L -->|Malicious| M[Alert Analyst]
    L -->|Suspicious| N[Review Queue]
    L -->|Benign| O[Auto-Close]
    
    M --> P[Dashboard]
    N --> P
```

---

## Detailed Version with All Components

```mermaid
flowchart TD
    subgraph INPUT["1. DATA SOURCES"]
        S1[SIEM]
        S2[EDR]
        S3[Firewall]
    end
    
    subgraph INGEST["2. INGESTION"]
        I1[Webhook /ingest]
        I2[Parser]
        I3[MITRE Mapper]
        I4[Severity Classifier]
    end
    
    subgraph QUEUE["3. QUEUE"]
        Q1[Queue Manager]
        Q2[Priority Queue]
        Q3[Standard Queue]
    end
    
    subgraph CONTEXT["4. CONTEXT"]
        C1[(Supabase)]
        C2[(ChromaDB)]
        C3[OSINT APIs]
    end
    
    subgraph AI["5. AI ANALYSIS"]
        A1[Input Guard]
        A2[Budget Tracker]
        A3[Context Builder]
        A4[Claude API]
        A5[Output Guard]
    end
    
    subgraph OUTPUT["6. OUTPUT"]
        O1{Verdict}
        O2[Malicious]
        O3[Suspicious]
        O4[Benign]
    end
    
    subgraph DASH["7. DASHBOARD"]
        D1[Analyst Console]
        D2[AI Transparency]
        D3[Performance]
    end
    
    %% Flow
    S1 --> I1
    S2 --> I1
    S3 --> I1
    I1 --> I2 --> I3 --> I4
    I4 --> Q1
    Q1 --> Q2
    Q1 --> Q3
    Q2 --> A1
    Q3 --> A1
    A1 --> A2 --> A3
    C1 --> A3
    C2 --> A3
    C3 --> A3
    A3 --> A4 --> A5
    A5 --> O1
    O1 --> O2
    O1 --> O3
    O1 --> O4
    O2 --> D1
    O3 --> D1
    O4 -.->|Auto-Close| C1
    C1 --> D1
    C1 --> D2
    C1 --> D3
```

---

## Simple Overview (Best for Presentations)

```mermaid
flowchart LR
    A[Security<br/>Alerts] --> B[Ingestion<br/>& Queue]
    B --> C[AI Analysis<br/>Pipeline]
    
    D[(Database)] --> C
    E[(Knowledge<br/>Base)] --> C
    
    C --> F[Claude AI]
    F --> G{Decision}
    
    G --> H[Analyst<br/>Dashboard]
    G --> I[Auto<br/>Close]
```

---

## 6-Phase AI Pipeline (Horizontal)

```mermaid
flowchart LR
    P1[Phase 1<br/>Security Gates] --> P2[Phase 2<br/>Optimization]
    P2 --> P3[Phase 3<br/>Context Gathering]
    P3 --> P4[Phase 4<br/>AI Analysis]
    P4 --> P5[Phase 5<br/>Validation]
    P5 --> P6[Phase 6<br/>Action]
    
    style P1 fill:#ffcdd2
    style P2 fill:#fff9c4
    style P3 fill:#c8e6c9
    style P4 fill:#bbdefb
    style P5 fill:#e1bee7
    style P6 fill:#b2dfdb
```

---

## RAG Knowledge Base

```mermaid
flowchart LR
    A[Alert] --> B[Query]
    B --> C[ChromaDB]
    
    subgraph C[ChromaDB Collections]
        C1[MITRE Techniques]
        C2[Historical Alerts]
        C3[Business Rules]
        C4[Attack Patterns]
        C5[Detection Rules]
    end
    
    C --> D[Combined Context]
    D --> E[Claude AI]
```

---

## Tech Stack Summary

```mermaid
flowchart LR
    subgraph Frontend
        R[React + Vite]
    end
    
    subgraph Backend
        F[Flask API]
    end
    
    subgraph AI
        CL[Claude API]
    end
    
    subgraph Storage
        S[(Supabase)]
        CH[(ChromaDB)]
        S3[AWS S3]
    end
    
    R <--> F
    F <--> CL
    F <--> S
    F <--> CH
    S -.-> S3
```
