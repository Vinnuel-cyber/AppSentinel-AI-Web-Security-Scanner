# AppSentinel AI Security Analyst (V8)

## Overview

AppSentinel **V8 – AI Security Analyst** is an enterprise-grade artificial intelligence integration designed for defensive application security operations. It bridges deterministic vulnerability scanner outputs (CVSS v4.0 scores, OWASP 2025 categories, CWE IDs, and HTTP evidence dumps) with defensive intelligence to provide:

1. **Vulnerability Root-Cause Diagnostics:** Deep technical analysis uncovering the architectural or coding defects responsible for detected flaws.
2. **Context-Aware Remediation Blueprints:** Production-ready secure code samples tailored to common web stacks (Python, Flask, SQLAlchemy, Jinja2, Nginx, Apache).
3. **Target Posture Synthesis:** Executive and technical security assessments summarizing compound risk, attack surface density, and remediation prioritization across authorized targets.
4. **Grounded Security Chat:** A natural-language security workbench where users can query scan results, understand risk vectors, and obtain actionable mitigation steps strictly scoped to their authorized database records.
5. **Deterministic Fallback Engine:** 100% offline, reproducible security rule engine ensuring all analyst capabilities remain operational without cloud API keys or external network dependencies.

---

## Architectural Principles

```
  +-------------------------------------------------------------+
  |                   Authenticated User / SOC                  |
  +-------------------------------------------------------------+
                                 |
                                 v
  +-------------------------------------------------------------+
  |              Flask AI Controller (/ai routes)               |
  |     - Strict Session Authentication & CSRF Validation       |
  |     - Multi-Tenant RBAC & Cross-User Isolation Enforcement   |
  +-------------------------------------------------------------+
                                 |
                                 v
  +-------------------------------------------------------------+
  |                    AIService & Orchestrator                 |
  |  +--------------------+             +--------------------+  |
  |  | ContextBuilder     |             | PromptManager      |  |
  |  | - DB RBAC Queries  |             | - Secret Redaction |  |
  |  | - Scope Isolation  |             | - Prompt Injection |  |
  |  +--------------------+             +--------------------+  |
  +-------------------------------------------------------------+
            |                                           |
    [Cloud AI Enabled]                         [Offline / Fallback]
            |                                           |
            v                                           v
  +-----------------------+                   +-----------------------+
  | OpenAI SDK (>=1.0.0)  |                   | FallbackEngine (V8)   |
  | - Responses API       |                   | - Offline Rule Engine |
  | - Chat Completions    |                   | - Deterministic OWASP |
  | - Retries & Backoff   |                   | - Code Remediation    |
  +-----------------------+                   +-----------------------+
            |                                           |
            +---------------------+---------------------+
                                  |
                                  v
  +-------------------------------------------------------------+
  |                      ResponseValidator                      |
  |    - Structural JSON Schema Verification                    |
  |    - Markdown Code Block Striping                           |
  |    - Strict Type and Confidence Normalization               |
  +-------------------------------------------------------------+
                                  |
                                  v
  +-------------------------------------------------------------+
  |                     Persistence & Audit                     |
  |     - AIAnalysis (Caching & Structured Results)             |
  |     - AIConversation & AIMessage (Chat History)             |
  |     - AIUsageLog (Token Accounting & Request Auditing)      |
  +-------------------------------------------------------------+
```

---

## Confidence Decoupling

A core architectural guarantee of AppSentinel is **confidence decoupling**:
- `Vulnerability.confidence` represents deterministic evidence confidence (`CONFIRMED`, `HIGH`, `MEDIUM`, `LOW`) calculated by scanner modules from HTTP responses and probe reflections.
- `AIAnalysis.ai_confidence` represents the analytical certainty of the AI or fallback engine (`HIGH`, `MEDIUM`, `LOW`).
- The AI Security Analyst is strictly an advisory engine and **never** modifies deterministic scanner findings, CVSS v4.0 vectors, OWASP mappings, or verification statuses.
