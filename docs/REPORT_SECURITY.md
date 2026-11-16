# AppSentinel Report Security & Download Defense (V9)

## 1. Multi-Tenant Authorization & IDOR Defenses

Reports contain detailed technical attack vectors and redacted proof-of-concept evidence. AppSentinel enforces multi-tenant isolation at every stage:

1. **Generation Guard:** `ReportService.generate_report` verifies that the requesting user owns both the target and the scan (`target.owner_id == user_id and scan.user_id == user_id`). Non-admin users attempting to generate reports against another tenant's scans are rejected with HTTP 400/403.
2. **Download Guard:** `GET /reports/download/<id>` verifies report ownership before file transmission. If user A attempts to download user B's report ID, the system returns HTTP 404 (IDOR blocked).
3. **Deletion Guard:** `DELETE /reports/<id>` strictly verifies ownership prior to unlinking files and removing database records.
4. **Admin Role:** Administrators (`role == 'ADMIN'`) maintain global audit visibility across all reports.

---

## 2. Path Traversal & Filesystem Hardening

To prevent directory traversal attacks (e.g. `../../etc/passwd` or outside directory writes):

- Filenames are sanitized using `werkzeug.utils.secure_filename`.
- Paths are resolved using `pathlib.Path.resolve()`.
- The resolved destination and download paths must pass `ReportService.is_safe_path`:
  ```python
  def is_safe_path(file_path: Path, base_dir: Path) -> bool:
      resolved_file = file_path.resolve()
      resolved_base = base_dir.resolve()
      return str(resolved_file).startswith(str(resolved_base))
  ```
- Any file path resolving outside `REPORT_FOLDER` is immediately blocked.

---

## 3. Evidence Sanitization & Redaction

Before writing evidence into PDF table cells, `SecurityDataCollector` passes all raw payload strings, snippets, and HTTP headers through `PromptManager.sanitize_untrusted_text`:
- AWS access keys (`AKIA...`) are replaced with `[REDACTED_AWS_KEY]`.
- Bare OpenAI API keys (`sk-...`) are replaced with `[REDACTED_API_KEY]`.
- Bare GitHub tokens (`ghp_...`) are replaced with `[REDACTED_GITHUB_TOKEN]`.
- Session tokens, cookies, and bearer tokens are masked.
- Raw passwords and private keys are scrubbed.

---

## 4. Distinction Between Findings and AI Advisories

In accordance with defensive application security ethics:
- Scanner findings represent deterministic facts verified during the scan window.
- AI Security Analyst content is clearly demarcated with advisory headers:
  > *"[AI Security Analyst Advisory – Provider: {provider} | Confidence: {ai_confidence}]"*
- AI explanations are never conflated with or presented as independently confirmed scanner findings.
