# setup this project run fast - 
- pip install -r requirements.txt

# import sql file phishing_guard.sql into xampp 
- phishing_guard.sql or write sql follow: schema.sql

# Run cmd -
 - python app.py or py app.py
 
# Admin Pannel access- 
- ('admin@gmail.com', 'admin123');

# Ensuring Secure Online Banking From Phishing

Research-friendly phishing detection prototype built with Flask, MySQL, and Bootstrap. It scores banking URLs for phishing risk based on HTTPS availability, domain age (WHOIS), and a pluggable external threat-intel check.

## Features
- URL input form with immediate risk verdict (safe vs phishing)
- Checks against local phishing URL database
- HTTPS reachability test
- Domain age check via WHOIS
- External API hook (mocked by default; swap with Google Safe Browsing or VirusTotal)
- Risk scoring with adjustable thresholds
- Results persisted to MySQL for audit/research

## Quick Start (Windows, WSL or Git Bash)
1. Install Python 3.10+ and MySQL Server. Enable phpMyAdmin if desired.
2. Create the schema:
   ```sql
   source schema.sql;
   ```
3. Set environment variables (use your credentials):
   ```bash
   export MYSQL_HOST=127.0.0.1
   export MYSQL_USER=root
   export MYSQL_PASSWORD=your_password
   export MYSQL_DATABASE=phishing_guard
   export MYSQL_PORT=3306
   # optional
   export GSB_API_KEY=your_google_safe_browsing_key
   export VT_API_KEY=your_virustotal_key
   ```
4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
5. Run the app:
   ```bash
   python app.py or py app.py
   ```
6. Visit `http://127.0.0.1:5000` and test URLs.

### Admin login (`/admin`)
- Set `SECRET_KEY` env var for sessions.
- Create an admin user in `users` with a hashed password:
  ```bash
  python - <<'PY'
  from werkzeug.security import generate_password_hash
  print(generate_password_hash("your_password"))
  PY
  ```
  Then insert into MySQL: `INSERT INTO users (email, password_hash) VALUES ('admin@example.com', '<hash>');`
- Visit `http://127.0.0.1:5000/admin` to log in, add bank whitelist entries, and view `phishing_urls` and `checked_urls`.

## Project Structure
- `app.py` — Flask app, routes, scoring flow, DB persistence.
- `config.py` — DB config, API keys, thresholds, timeouts.
- `templates/index.html` — Bootstrap UI for input and results.
- `static/style.css` — Minimal styling.
- `schema.sql` — MySQL schema and seed data.
- `requirements.txt` — Python dependencies.
- `bank_whitelist` table — seeded with major Malaysian commercial bank domains for quick legitimacy checks before running other signals.

## Risk Scoring Logic
- Start at 0.
- +30 if HTTPS unreachable.
- +30 if domain age < 365 days.
- +40 if external API result is `suspicious`.
- Score capped at 100.
- Verdict: score ≥ 60 → phishing, else safe.

## External API Integration (swap the mock)
Replace `external_api_check` in `app.py` with real calls:
- **Google Safe Browsing**: send `threatInfo` with URL; treat matches as suspicious.
- **VirusTotal URL scan**: submit URL, poll report; treat malicious/suspicious as risky.
Keep timeouts short, add caching, and handle API rate limits.

## Security Best Practices
- Use HTTPS for your Flask app (behind a reverse proxy) in production.
- Validate and normalize URLs before processing; avoid SSRF by disallowing private IP targets if you extend network fetching.
- Store secrets in env vars or a secrets manager; never commit keys.
- Principle of least privilege for MySQL user; avoid `root` in production.
- Enable prepared statements (already used) to prevent SQL injection.
- Rate-limit the endpoint to prevent abuse; add auth if exposed publicly.
- Log security-relevant events but avoid storing sensitive PII.
- Keep dependencies patched and pin versions (see `requirements.txt`).

## Research Notes
- `checked_urls` table provides auditability of signals and scores.
- `phishing_urls` can be bulk-fed with feeds (PhishTank, OpenPhish); add deduplication/normalization before inserts.
- The WHOIS library may return variable formats; code handles list/datetime and falls back to `None`.
- Network calls use short timeouts to keep UI responsive.

## Troubleshooting
- Cannot connect to DB: verify `MYSQL_HOST/PORT/USER/PASSWORD/DB`, ensure MySQL is running, and user has rights.
- WHOIS failures: some registries block queries; result will show domain age as `Unknown` but flow continues.
- HTTPS check shows false negatives: some sites block `HEAD`; switch to `GET` in `check_https_status` if needed.

## Next Steps
- Add authentication and per-user history.
- Integrate Redis caching for WHOIS/Intel responses.
- Add background job for external API scans to avoid slow UI.
- Build automated tests (pytest) for scoring rules and DB access.

"# Bank_phishing_url-" 
