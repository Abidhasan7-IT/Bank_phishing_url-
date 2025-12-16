import os

# Basic configuration for DB
DB_CONFIG = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "user": os.getenv("MYSQL_USER", "root"),
    "password": os.getenv("MYSQL_PASSWORD", ""),
    "database": os.getenv("MYSQL_DATABASE", "phishing_guard"),
    "port": int(os.getenv("MYSQL_PORT", "3306")),
}

# Flask secret key 
SECRET_KEY = os.getenv("SECRET_KEY", "52215122505")

# External API placeholders 
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GSB_API_KEY", "AIzaSyC0oJ-71sQY0Tg93_3vGj2524bE47g-7U")
VIRUSTOTAL_KEY = os.getenv("VT_API_KEY", "d30c1313984f1520c132273058c4867420a601126a32f85421b4721977537568")

# Risk scoring thresholds
RISK_THRESHOLD = {
    "high": 50,  # score >= 50 -> phishing (lowered to catch more suspicious URLs)
    "medium": 30,  # score >= 30 -> suspicious/warning
}

# Timeout defaults
HTTP_TIMEOUT = 5


