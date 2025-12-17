import datetime
import ipaddress
import logging
import os
import socket
from functools import wraps
from urllib.parse import urlparse

import mysql.connector
import requests
import whois
from werkzeug.security import check_password_hash
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY


def get_db_connection():
    """Create a new MySQL connection using mysql-connector-python."""
    try:
        conn = mysql.connector.connect(**config.DB_CONFIG)
        return conn
    except mysql.connector.Error as exc:
        logger.error("Database connection failed: %s", exc)
        raise


def normalize_url(raw_url: str) -> str:
    """Ensure the URL has a scheme and return normalized string."""
    if not raw_url:
        return ""
    parsed = urlparse(raw_url if "://" in raw_url else f"http://{raw_url}")
    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path or ''}"
    return normalized


def is_url_in_phishing_db(conn, url: str) -> bool:
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM phishing_urls WHERE url = %s LIMIT 1", (url,))
    result = cursor.fetchone()
    cursor.close()
    return bool(result)


def check_https_status(url: str) -> bool:
    """Return True if HTTPS is reachable; False otherwise."""
    parsed = urlparse(url)
    https_url = parsed._replace(scheme="https").geturl()
    try:
        response = requests.head(
            https_url,
            allow_redirects=True,
            timeout=config.HTTP_TIMEOUT,
            verify=True,
        )
        return response.status_code < 400
    except (requests.RequestException, socket.error) as exc:
        logger.info("HTTPS check failed for %s: %s", url, exc)
        return False


def get_domain_age_days(url: str) -> int | None:
    """Return domain age in days, or None if unavailable."""
    try:
        # whois expects a bare hostname (no port)
        domain = urlparse(url).netloc.split(":")[0].lower()
        if not domain:
            return None

        record = whois.whois(domain)
        created = record.creation_date

        # Normalize creation_date which may be list/str/date/datetime depending on registrar
        if isinstance(created, list):
            created = next((c for c in created if c), None)
        if isinstance(created, str):
            # Try common ISO-ish formats before giving up
            for fmt in (
                "%Y-%m-%d",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S%z",
            ):
                try:
                    created = datetime.datetime.strptime(created, fmt)
                    break
                except ValueError:
                    continue
            else:
                try:
                    # fromisoformat handles many variations including offsets
                    created = datetime.datetime.fromisoformat(created)
                except ValueError:
                    created = None
        if isinstance(created, datetime.date) and not isinstance(
            created, datetime.datetime
        ):
            created = datetime.datetime.combine(created, datetime.time.min)

        if not isinstance(created, datetime.datetime):
            return None

        # Assume UTC if the datetime is naive
        if created.tzinfo is None:
            created = created.replace(tzinfo=datetime.timezone.utc)

        age = datetime.datetime.now(datetime.timezone.utc) - created
        return age.days
    except Exception as exc:  # whois library raises broad exceptions
        logger.info("WHOIS lookup failed for %s: %s", url, exc)
        return None


def external_api_check(url: str) -> str:
    """
    Placeholder for Google Safe Browsing or VirusTotal.
    For research/demo, return 'suspicious' if domain age is unavailable or URL looks odd.
    """
    parsed = urlparse(url)
    netloc = parsed.netloc.lower()
    
    logger.info("External API check for URL: %s, netloc: %s", url, netloc)
    
    # Check for suspicious TLDs (check if domain ends with suspicious TLD)
    suspicious_tlds = [".ru", ".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".click"]
    for tld in suspicious_tlds:
        if netloc.endswith(tld) or tld in netloc:
            logger.info("Suspicious TLD detected: %s", tld)
            return "suspicious"
    
    # Check for suspicious patterns
    suspicious_patterns = [
        "xn--",  # Punycode domains
        "bit.ly", "tinyurl", "short.link",  # URL shorteners (often used in phishing)
    ]
    
    for pattern in suspicious_patterns:
        if pattern in netloc:
            logger.info("Suspicious pattern detected: %s", pattern)
            return "suspicious"
    
    # Check for suspicious subdomain patterns
    # Treat only very deep subdomain chains as suspicious. Common banking domains
    # like 'www.bank.com.my' have several dots but are usually legitimate.
    if netloc.count(".") > 3:  # Excessive subdomains
        logger.info("Multiple subdomains detected")
        return "suspicious"
    
    # Check for typosquatting patterns (common in phishing) - check entire netloc, not just parts
    suspicious_keywords = ["secure", "verify", "update", "login", "account", "banking"]
    for keyword in suspicious_keywords:
        if keyword in netloc.lower():
            logger.info("Suspicious keyword detected: %s in netloc", keyword)
            return "suspicious"
    
    logger.info("External API check returned: clean")
    return "clean"


def check_typosquatting(conn, url: str) -> bool:
    """Check if URL is typosquatting a bank domain."""
    if not conn:
        return False
        
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        domain = netloc.split(":")[0]  # Remove port
        
        cursor = conn.cursor()
        cursor.execute("SELECT domain FROM bank_whitelist")
        bank_domains = [row[0] for row in cursor.fetchall()]
        cursor.close()
        
        # Check if domain contains bank domain names (typosquatting)
        bank_keywords = ["maybank", "cimb", "public", "rhb", "hongleong", "hlb", 
                         "ambank", "bankislam", "alliance", "hsbc", "ocbc", "uob",
                         "bankrakyat", "affin", "muamalat", "sc.com"]
        
        # Extract main domain part (without TLD) for better matching
        domain_parts = domain.split(".")
        main_domain = domain_parts[0] if domain_parts else domain
        
        for keyword in bank_keywords:
            # Check if keyword appears in the domain (not just exact match)
            if keyword in domain.lower():
                # If it contains bank keyword but is not in whitelist, likely typosquatting
                if domain not in bank_domains:
                    logger.info("Typosquatting detected: %s contains bank keyword '%s'", domain, keyword)
                    return True
    except Exception as exc:
        logger.error("Error in typosquatting check: %s", exc)
        return False
    
    return False


def calculate_risk_score(
    https_ok: bool, domain_age: int | None, external_result: str, url: str = "", conn=None
) -> int:
    score = 0
    parsed = urlparse(url)
    netloc = parsed.netloc.lower()
    
    logger.info("Calculating risk score for: %s (netloc: %s)", url, netloc)
    logger.info("Inputs - HTTPS: %s, Domain Age: %s, External: %s", https_ok, domain_age, external_result)
    
    # Base risk factors
    if not https_ok:
        score += 30  # No HTTPS
        logger.info("No HTTPS detected, score now: %d", score)
    else:
        # Even with HTTPS, check for other suspicious indicators
        score += 5  # Small base risk for any URL check
    
    # Domain age checks
    if domain_age is None or domain_age == 0:
        # Domain age unavailable is suspicious (could be new or hidden)
        score += 35
        logger.info("Domain age is None/0, adding 35 points, score now: %d", score)
    elif domain_age < 365:
        score += 30  # Domain younger than 1 year
        logger.info("Domain age %d days (< 365), adding 30 points, score now: %d", domain_age, score)
    elif domain_age < 730:
        score += 10  # Domain less than 2 years old
        logger.info("Domain age %d days (< 730), adding 10 points, score now: %d", domain_age, score)
    
    # External API result
    if external_result == "suspicious":
        score += 40  # External intel flagged
        logger.info("External API flagged as suspicious, adding 40 points, score now: %d", score)
    
    # Check for typosquatting (bank domain imitation)
    if conn:
        if check_typosquatting(conn, url):
            score += 45  # High risk for typosquatting
            logger.info("Typosquatting detected, adding 45 points, score now: %d", score)
    
    # Additional heuristics for URL patterns
    # Check for suspicious TLDs (check if domain ends with suspicious TLD or contains it)
    suspicious_tlds = [".ru", ".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".click"]
    tld_found = False
    for tld in suspicious_tlds:
        if netloc.endswith(tld) or tld in netloc:
            if not tld_found:  # Only add points once
                score += 25
                tld_found = True
                logger.info("Suspicious TLD %s detected, adding 25 points, score now: %d", tld, score)
            break
    
    # Check for URL shorteners (often used in phishing)
    url_shorteners = ["bit.ly", "tinyurl.com", "short.link", "t.co", "goo.gl"]
    if any(shortener in netloc for shortener in url_shorteners):
        score += 30
        logger.info("URL shortener detected, adding 30 points, score now: %d", score)
    
    # Check for IP addresses instead of domains (very suspicious)
    try:
        domain_part = netloc.split(":")[0]  # Remove port if present
        ipaddress.ip_address(domain_part)
        score += 50  # Direct IP address is highly suspicious
        logger.info("IP address detected, adding 50 points, score now: %d", score)
    except (ValueError, AttributeError):
        pass  # Not an IP, which is normal
    
    # Check for excessive subdomains
    if netloc.count(".") > 3:
        score += 20
        logger.info("Excessive subdomains detected, adding 20 points, score now: %d", score)
    
    # Check for suspicious keywords in domain (with or without hyphens)
    phishing_keywords = ["secure", "verify", "update", "login", "account", "banking"]
    domain_parts = netloc.split(".")
    keyword_found = False
    for part in domain_parts:
        for keyword in phishing_keywords:
            if keyword in part.lower():
                if not keyword_found:  # Only add points once
                    score += 25
                    keyword_found = True
                    logger.info("Suspicious keyword '%s' found in domain part '%s', adding 25 points, score now: %d", keyword, part, score)
                break
        if keyword_found:
            break
    
    # Check for very long domains (common in phishing)
    if len(netloc) > 50:
        score += 15
        logger.info("Very long domain detected, adding 15 points, score now: %d", score)
    
    final_score = min(score, 100)
    logger.info("Final risk score for %s: %d", url, final_score)
    return final_score


def add_to_phishing_db(conn, url: str, source: str = "auto_detected"):
    """Add a URL to the phishing_urls table if not already present."""
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO phishing_urls (url, source)
            VALUES (%s, %s)
            ON DUPLICATE KEY UPDATE source = VALUES(source)
            """,
            (url, source),
        )
        conn.commit()
        logger.info("Added URL to phishing database: %s", url)
    except mysql.connector.IntegrityError:
        # URL already exists, that's fine
        conn.rollback()
        logger.debug("URL already in phishing database: %s", url)
    except mysql.connector.Error as exc:
        conn.rollback()
        logger.error("Failed to add URL to phishing database: %s", exc)
    finally:
        cursor.close()


def save_checked_url(
    conn,
    url: str,
    https_status: bool,
    domain_age: int | None,
    external_api_result: str,
    risk_score: int,
    final_status: str,
):
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO checked_urls
        (url, https_status, domain_age, external_api_result, risk_score, final_status)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (
            url,
            int(https_status),
            domain_age if domain_age is not None else None,
            external_api_result,
            risk_score,
            final_status,
        ),
    )
    conn.commit()
    cursor.close()


def login_required(view_func):
    """Redirect to admin login if no active admin session."""

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("admin_id"):
            return redirect(url_for("admin"))
        return view_func(*args, **kwargs)

    return wrapped


def fetch_table_rows(conn, table_name: str, limit: int = 200):
    """Return recent rows from a known table using a dict cursor."""
    allowed = {"bank_whitelist", "phishing_urls", "checked_urls"}
    if table_name not in allowed:
        raise ValueError("Invalid table name requested")
    cursor = conn.cursor(dictionary=True)
    cursor.execute(f"SELECT * FROM {table_name} ORDER BY id DESC LIMIT %s", (limit,))
    rows = cursor.fetchall()
    cursor.close()
    return rows


def get_latest_phishing_urls(conn, limit: int = 10):
    """Return the latest phishing URLs from the database."""
    return fetch_table_rows(conn, "phishing_urls", limit)


def get_admin_by_email(conn, email: str):
    """Fetch admin/user record by email."""
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT id, email, password_hash FROM users WHERE email = %s LIMIT 1",
        (email,),
    )
    user = cursor.fetchone()
    cursor.close()
    return user


def verify_password(stored_hash: str | None, candidate: str) -> bool:
    """
    Accept either a Werkzeug hash or a legacy plain-text password.
    Plain-text fallback is for compatibility with existing seed data.
    """
    if not stored_hash:
        return False
    # Werkzeug hashes usually start with methods like 'pbkdf2:'
    if stored_hash.startswith(("pbkdf2:", "scrypt:", "bcrypt$")):
        return check_password_hash(stored_hash, candidate)
    # Fallback to direct compare for legacy plain-text entries
    return stored_hash == candidate


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_template("index.html", result=None)

    raw_url = request.form.get("url", "").strip()
    normalized_url = normalize_url(raw_url)
    if not normalized_url:
        return render_template(
            "index.html",
            result={"error": "Please provide a valid URL."},
        )

    # Basic validation: require a full domain, not just 'https://www'
    parsed = urlparse(normalized_url)
    host = parsed.netloc.split(":")[0].lower()
    if not host or host == "www" or "." not in host:
        return render_template(
            "index.html",
            result={
                "error": "Please enter a full banking domain (for example: https://www.bank.com or https://www.muamalat.com.my), not just https://www.",
            },
        )

    conn = get_db_connection()
    try:
        # Step 1: Check against phishing DB
        if is_url_in_phishing_db(conn, normalized_url):
            latest_phishing_urls = get_latest_phishing_urls(conn, limit=10)
            result = {
                "url": normalized_url,
                "https_status": False,
                "domain_age": None,
                "external_api_result": "phishing_db_hit",
                "risk_score": 100,
                "final_status": "phishing",
                "reason": "URL found in phishing database",
                "latest_phishing_urls": latest_phishing_urls,
            }
            save_checked_url(
                conn,
                normalized_url,
                False,
                None,
                "phishing_db_hit",
                100,
                "phishing",
            )
            return render_template("index.html", result=result)

        # Step 2: HTTPS check
        https_ok = check_https_status(normalized_url)

        # Step 3: Domain age check
        domain_age = get_domain_age_days(normalized_url)
        logger.info("Domain age result for %s: %s", normalized_url, domain_age)

        # Step 4: External API (mock)
        external_result = external_api_check(normalized_url)
        logger.info("External API result for %s: %s", normalized_url, external_result)

        # Step 5: Risk score & classification
        logger.info("=== Starting Risk Score Calculation ===")
        logger.info("URL: %s", normalized_url)
        logger.info("HTTPS OK: %s", https_ok)
        logger.info("Domain Age: %s (type: %s)", domain_age, type(domain_age))
        logger.info("External Result: %s", external_result)
        logger.info("Connection available: %s", conn is not None)
        
        risk_score = calculate_risk_score(https_ok, domain_age, external_result, normalized_url, conn)
        
        logger.info("Calculated Risk Score: %d", risk_score)
        logger.info("Risk Thresholds (high/medium): %d / %d", config.RISK_THRESHOLD["high"], config.RISK_THRESHOLD["medium"])

        # Map numeric score to human-readable risk level and final status
        if risk_score >= config.RISK_THRESHOLD["high"]:
            risk_level = "high"
            final_status = "phishing"
        elif risk_score >= config.RISK_THRESHOLD["medium"]:
            risk_level = "medium"
            final_status = "suspicious"
        else:
            risk_level = "low"
            final_status = "safe"
        
        # Log the risk assessment for debugging
        logger.info(
            "=== Final Result === URL: %s | HTTPS: %s | Domain Age: %s | External: %s | Score: %d | Status: %s",
            normalized_url, https_ok, domain_age, external_result, risk_score, final_status
        )

        result = {
            "url": normalized_url,
            "https_status": https_ok,
            "domain_age": domain_age,
            "external_api_result": external_result,
            "risk_score": risk_score,
            "final_status": final_status,
            "risk_level": risk_level,
        }

        # If phishing detected, add to phishing database and fetch latest phishing URLs
        if final_status == "phishing":
            add_to_phishing_db(conn, normalized_url, source="auto_detected")
            result["latest_phishing_urls"] = get_latest_phishing_urls(conn, limit=10)

        save_checked_url(
            conn,
            normalized_url,
            https_ok,
            domain_age,
            external_result,
            risk_score,
            final_status,
        )

        return render_template("index.html", result=result)
    finally:
        conn.close()


@app.route("/admin", methods=["GET", "POST"])
def admin():
    """Admin login page."""
    if session.get("admin_id"):
        return redirect(url_for("admin_dashboard"))

    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not email or not password:
            error = "Email and password are required."
        else:
            conn = get_db_connection()
            try:
                user = get_admin_by_email(conn, email)
            finally:
                conn.close()

            if user and verify_password(user["password_hash"], password):
                session["admin_id"] = user["id"]
                session["admin_email"] = user["email"]
                return redirect(url_for("admin_dashboard"))
            error = "Invalid email or password."

    return render_template("admin.html", login_error=error, data=None)


@app.route("/admin/dashboard")
@login_required
def admin_dashboard():
    """Admin dashboard showing whitelists and URL checks."""
    conn = get_db_connection()
    try:
        data = {
            "bank_whitelist": fetch_table_rows(conn, "bank_whitelist"),
            "phishing_urls": fetch_table_rows(conn, "phishing_urls"),
            "checked_urls": fetch_table_rows(conn, "checked_urls"),
        }
    finally:
        conn.close()

    return render_template("admin.html", login_error=None, data=data)


@app.route("/admin/whitelist", methods=["POST"])
@login_required
def add_bank_whitelist():
    """Allow admin to add a new bank whitelist entry."""
    bank_name = request.form.get("bank_name", "").strip()
    domain = request.form.get("domain", "").strip().lower()

    if not bank_name or not domain:
        flash("Bank name and domain are required.", "danger")
        return redirect(url_for("admin_dashboard"))

    conn = get_db_connection()
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO bank_whitelist (bank_name, domain)
            VALUES (%s, %s)
            """,
            (bank_name, domain),
        )
        conn.commit()
        flash("Bank domain added to whitelist.", "success")
    except mysql.connector.IntegrityError:
        conn.rollback()
        flash("Domain already exists in whitelist.", "warning")
    finally:
        if cursor is not None:
            cursor.close()
        conn.close()

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/whitelist/<int:entry_id>/delete", methods=["POST"])
@login_required
def delete_bank_whitelist(entry_id: int):
    """Allow admin to delete an existing bank whitelist entry."""
    conn = get_db_connection()
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM bank_whitelist WHERE id = %s", (entry_id,))
        conn.commit()
        if cursor.rowcount:
            flash("Bank domain removed from whitelist.", "success")
        else:
            flash("Whitelist entry not found.", "warning")
    except mysql.connector.Error as exc:
        conn.rollback()
        logger.error("Failed to delete whitelist entry %s: %s", entry_id, exc)
        flash("Could not delete whitelist entry.", "danger")
    finally:
        if cursor is not None:
            cursor.close()
        conn.close()

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/logout")
@login_required
def admin_logout():
    session.clear()
    return redirect(url_for("admin"))

# this is for testing purposes only
@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

