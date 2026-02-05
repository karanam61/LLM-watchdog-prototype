# Architecture Diagrams

Supplementary diagrams for presentations and documentation. Copy any diagram to [mermaid.live](https://mermaid.live) to generate PNG/SVG exports.

## Linear Flow (Left to Right)

```mermaid
flowchart LR
    A[SIEM / EDR / Firewall] --> B[Webhook API]
    B --> C[Parser]
    C --> D[MITRE Mapper]
    D --> E[Severity Classifier]
    E --> F{Queue Manager}
    F --> G[Priority Queue]
    F --> H[Standard Queue]
    G --> I[Security Guard]
    H --> I
    I --> J[Context Builder]
    K[(Supabase DB)] --> J
    L[(ChromaDB RAG)] --> J
    M[OSINT APIs] --> J
    J --> N[Claude AI]
    N --> O{Verdict}
    O --> P[Malicious]
    O --> Q[Suspicious]
    O --> R[Benign]
    P --> S[Dashboard]
    Q --> S
    R --> T[Auto-Close]
    K -.-> U[S3 Backup]
```

## Vertical Flow

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

## Simple Overview

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

## AI Pipeline Phases

```mermaid
flowchart LR
    P1[Phase 1<br/>Security Gates] --> P2[Phase 2<br/>Optimization]
    P2 --> P3[Phase 3<br/>Context Gathering]
    P3 --> P4[Phase 4<br/>AI Analysis]
    P4 --> P5[Phase 5<br/>Validation]
    P5 --> P6[Phase 6<br/>Action]
```

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

## Tech Stack

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
