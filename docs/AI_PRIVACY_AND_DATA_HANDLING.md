# AppSentinel Privacy and Data Handling Policy (V8)

## 1. Principles

AppSentinel is committed to enterprise data privacy, multi-tenant isolation, and minimal data exposure:

1. **Multi-Tenant Scoping:** Non-administrative users can only access, query, or analyze targets and findings they explicitly own. Cross-tenant queries are blocked with HTTP 403 Forbidden.
2. **Zero Involuntary Cloud Exposure:** By default, AppSentinel operates in offline mode (`AI_ENABLED=false`). When offline, the deterministic `FallbackEngine` handles all analysis without generating any external network traffic.
3. **Data Minimization:** AI prompts include only confirmed finding metadata, redacted parameter names, and truncated evidence snippets necessary for remediation synthesis. Full database dumps or unnecessary server metadata are never sent to external providers.
4. **Credential Pre-Scrubbing:** All session tokens, API keys, private keys, and passwords detected in scanner output are automatically redacted before prompts are constructed.
5. **Audit Logging:** Every AI inference request, fallback execution, and token consumption metric is recorded in `AIUsageLog` for transparency and administrative auditing.
