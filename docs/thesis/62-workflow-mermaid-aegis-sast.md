# Workflow Mermaid Don Gian Cho Aegis-SAST

## 1. Workflow Tong The De Ve Lai Trong Excalidraw

```mermaid
flowchart LR
    A[Input<br/>CLI / Dashboard / CI / Benchmark] --> B[Repo Intake]
    B --> C[Phat hien ngon ngu<br/>framework / scan profile]
    C --> D[Detection Core]
    D --> E[Raw Findings]
    E --> F[Finding Normalization]
    F --> G[Evidence Bundle]
    G --> H[Multi-Agent Triage]
    H --> I[Triage Decision<br/>status / confidence / explanation]
    I --> J[Reports<br/>JSON / Markdown / SARIF]
    J --> K[Dashboard / Review Console]
    K --> L[Reviewer Feedback]
    L --> M[Review Memory / FP Patterns]
    M --> H
    J --> N[Benchmark Scoring]
    N --> O[Aegis vs Semgrep<br/>Precision / Recall / F1]
    I --> P[Remediation Draft]
    P --> Q[Rescan Validation]
    Q --> F
```

## 2. Workflow Multi-Agent Don Gian

```mermaid
flowchart LR
    A[Normalized Finding<br/>+ Evidence] --> B[Auditor]
    B --> C{Du bang chung chua?}
    C -->|Co| E[Judge]
    C -->|Chua / de FP| D[Skeptic]
    D --> E
    E --> F[Triage Decision]
    F --> G[status]
    F --> H[confidence]
    F --> I[reason codes]
    F --> J[explanation]
    F --> K[manual review]
    K --> L[Dashboard Review]
    L --> M[Reviewer Feedback]
    M --> N[Triage Memory]
    N --> B
    N --> D
```

## 3. Neu Muon Ve Bang Box Trong Excalidraw

Thu tu cac khoi nen dat tu trai qua phai:

1. Input
2. Repo Intake
3. Detection Core
4. Raw Findings
5. Finding Normalization
6. Evidence Bundle
7. Multi-Agent Triage
8. Triage Decision
9. Reports
10. Dashboard / Review
11. Reviewer Feedback
12. Review Memory
13. Benchmark Scoring
14. Aegis vs Semgrep
15. Remediation Draft
16. Rescan Validation
