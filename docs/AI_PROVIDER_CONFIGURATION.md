# AppSentinel AI Provider Configuration Guide (V8)

## Configuration Variables

Configure the AI Security Analyst module using environment variables or your `.env` configuration file:

| Variable | Type | Default | Description |
|---|---|---|---|
| `AI_ENABLED` | Boolean | `false` | Enable or disable cloud AI integration. When false, the deterministic fallback engine is used. |
| `AI_PROVIDER` | String | `openai` | AI provider identifier (e.g. `openai`). |
| `OPENAI_API_KEY` | String | `""` | Official OpenAI API authentication key (`sk-...`). |
| `OPENAI_MODEL` | String | `gpt-4o-mini` | Model identifier for analysis and chat (e.g. `gpt-4o-mini`, `gpt-4o`). |
| `AI_REQUEST_TIMEOUT` | Integer | `30` | Request timeout in seconds before failing over to fallback. |
| `AI_MAX_OUTPUT_TOKENS` | Integer | `2000` | Maximum token ceiling per inference request. |
| `AI_DAILY_LIMIT_PER_USER` | Integer | `50` | Maximum AI requests allowed per user per UTC day. |

---

## Operating Modes

### 1. Offline Mode (Default)
```bash
AI_ENABLED=false
```
All diagnostic analyses, posture assessments, and security chats are powered by `FallbackEngine`, which utilizes pre-calibrated OWASP 2025 mappings, CVSS v4.0 metrics, and Python/Flask secure coding catalogs. No API key or internet access is required.

### 2. Cloud AI Mode (OpenAI Responses API)
```bash
AI_ENABLED=true
AI_PROVIDER=openai
OPENAI_API_KEY=sk-proj-your-api-key-here
OPENAI_MODEL=gpt-4o-mini
AI_REQUEST_TIMEOUT=30
AI_MAX_OUTPUT_TOKENS=2000
AI_DAILY_LIMIT_PER_USER=50
```
In this mode, AppSentinel calls `client.responses.create(...)` with automatic exponential backoff retry for transient network errors, strict JSON schema validation, and graceful failover to `FallbackEngine` if rate limits or quota boundaries are encountered.
