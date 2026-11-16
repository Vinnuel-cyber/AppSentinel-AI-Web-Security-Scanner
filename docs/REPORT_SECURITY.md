# AppSentinel Report Security & Download Defense (V9)

## 1. Multi-Tenant Authorization & IDOR Defenses

Reports contain detailed technical attack vectors and redacted proof-of-concept evidence. AppSentinel enforces multi-tenant isolation at every stage:

1. **Generation Guard:** `ReportService.generate_report` verifies that the requesting user owns both the target and the scan (`target.owner_id == user_id and scan.user_id == user_id`). Non-admin users attempting to generate reports against another tenant's scans are rejected with HTTP 400/403.
2. **Download Guard:** `GET /reports/download/<id>` verifies report ownership before file transmission. If user A attempts to download user B's report ID, the system returns HTTP 404 (IDOR blocked).
3. **Deletion Guard:** `DELETE /reports/<id>` strictly verifies ownership prior to unlinking files and removing database records.
4. **Admin Role:** Administrators (`role == 'ADMIN'`) maintain global audit visibility across all reports.

---

## 2. Path Traversal & Filesystem Hardening

To prevent directory traversal attacks (e.g. `../../etc/passwd`, prefix collisions like `reports_backup`, or symlink breakouts):

- Filenames are sanitized using `werkzeug.utils.secure_filename`.
- Paths are resolved using `pathlib.Path.resolve()`.
- The resolved destination and download paths must pass `ReportService.is_safe_path`, which uses `Path.relative_to()` rather than string `startswith()` to eliminate prefix collisions and disallows the root directory itself:
  ```python
  def is_safe_path(file_path: Path, base_dir: Path) -> bool:
      resolved_file = file_path.resolve()
      resolved_base = base_dir.resolve()
      if resolved_file == resolved_base:
          return False
      resolved_file.relative_to(resolved_base)
      return True
  ```
- Any file path resolving outside `REPORT_FOLDER` is immediately blocked.
- Internal server filesystem paths (`file_path`) are excluded from `Report.to_dict()` JSON serialization to prevent server directory layout disclosure.

---

## 3. PDF Integrity & Tamper Verification

Every generated report has its SHA-256 cryptographic digest computed and stored in `Report.file_hash`:
- Upon download (`GET /reports/download/<id>`), `ReportService.get_report_file_for_download` reads the disk file and recalculates its SHA-256 hash.
- If the disk file content has been altered, tampered with, or corrupted, the download is rejected with an HTTP 400 error (`"Report integrity verification failed"`).
- Missing files on disk return HTTP 404 cleanly.

---

## 4. Evidence Sanitization & Markup Injection Defense

Before writing evidence into PDF table cells and flowables:
1. **Secret & Credential Redaction:**
   `SecurityDataCollector` passes all raw payload strings, snippets, and HTTP headers through `PromptManager.sanitize_untrusted_text`:
   - AWS access keys (`AKIA...`) are replaced with `[REDACTED_AWS_KEY]`.
   - Bare OpenAI API keys (`sk-...`) are replaced with `[REDACTED_API_KEY]`.
   - Bare GitHub tokens (`ghp_...`) are replaced with `[REDACTED_GITHUB_TOKEN]`.
   - Session tokens, cookies, and bearer tokens are masked (`Bearer [REDACTED_TOKEN]`, `session=[REDACTED_COOKIE]`).
   - Raw passwords and private keys are scrubbed.

2. **ReportLab Markup & Entity Escaping:**
   ReportLab `Paragraph` interprets XML tags (`<b>`, `<font>`, etc.). Raw evidence containing HTML/XML (such as `<script>`, unclosed tags, or ampersands) will crash the parser with `ValueError: paraparser: syntax error`.
   All untrusted strings, targets, URLs, parameters, payloads, code snippets, and descriptions are escaped via `html.escape(..., quote=False)` before rendering into ReportLab flowables, preventing XML parsing denial-of-service.

---

## 5. Distinction Between Findings and AI Advisories

In accordance with defensive application security ethics:
- Scanner findings represent deterministic facts verified during the scan window.
- AI Security Analyst content is clearly demarcated with advisory headers:
  > *"[AI Security Analyst Advisory – Provider: {provider} | Confidence: {ai_confidence}]"*
- AI explanations are never conflated with or presented as independently confirmed scanner findings.
