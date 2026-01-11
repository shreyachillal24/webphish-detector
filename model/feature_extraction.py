import re
import tldextract
import whois
from datetime import datetime
import requests
from urllib.parse import urlparse

# -------------------------------------------------
# URL VALIDATION (HARD GATE)
# -------------------------------------------------
def is_valid_url(url):
    try:
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False
        if not parsed.netloc:
            return False

        host = parsed.netloc.lower()

        # IP address
        if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host):
            return True

        # Domain name (must contain dot and valid chars)
        if "." in host and re.fullmatch(r"[a-z0-9.-]+", host):
            return True

        return False
    except:
        return False


# -------------------------------------------------
# DOMAIN AGE RISK (FIXED)
# -------------------------------------------------
def domain_age_score(url):
    try:
        domain = tldextract.extract(url).registered_domain
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return 0  # unknown → neutral (NOT risky)

        age_days = (datetime.now() - creation_date).days
        return 1 if age_days < 30 else 0
    except:
        return 0  # failure → neutral


# -------------------------------------------------
# URL STRUCTURAL FEATURES (ML FEATURES)
# -------------------------------------------------
SHORTENERS = ["bit.ly", "goo.gl", "tinyurl", "t.co", "ow.ly"]

def having_ip_address(url):
    return 1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0

def url_length(url):
    return len(url)

def shortening_service(url):
    return 1 if any(s in url for s in SHORTENERS) else 0

def having_at_symbol(url):
    return 1 if "@" in url else 0

def double_slash_redirecting(url):
    return 1 if url.count("//") > 1 else 0

def prefix_suffix(url):
    domain = tldextract.extract(url).domain
    return 1 if "-" in domain else 0

def having_subdomain(url):
    return 1 if url.count(".") > 2 else 0

def https_token(url):
    return 1 if url.startswith("https") else 0


# -------------------------------------------------
# DOMAIN AGE (ML FEATURE – STABLE)
# -------------------------------------------------
def age_of_domain(url):
    try:
        domain = tldextract.extract(url).registered_domain
        w = whois.whois(domain)
        cd = w.creation_date

        if isinstance(cd, list):
            cd = cd[0]

        if not cd:
            return 0

        age = (datetime.now() - cd).days
        return 1 if age >= 365 else 0
    except:
        return 0


# -------------------------------------------------
# FEATURE VECTOR FOR ML MODEL
# -------------------------------------------------
def extract_features(url):
    return [
        having_ip_address(url),
        url_length(url),
        shortening_service(url),
        having_at_symbol(url),
        double_slash_redirecting(url),
        prefix_suffix(url),
        having_subdomain(url),
        https_token(url),
        age_of_domain(url),
    ]


# -------------------------------------------------
# BRAND IMPERSONATION (FIXED – NO GOOGLE FALSE POSITIVE)
# -------------------------------------------------
KNOWN_BRANDS = {
    "google": ["google.com", "google.co.in"],
    "paypal": ["paypal.com"],
    "apple": ["apple.com"],
    "microsoft": ["microsoft.com"]
}

def brand_keyword_score(url):
    url = url.lower()

    for brand, legit_domains in KNOWN_BRANDS.items():
        if brand in url:
            # brand present but NOT official domain → phishing
            if not any(domain in url for domain in legit_domains):
                return 1
            else:
                return 0
    return 0


# -------------------------------------------------
# HTML INTENT ANALYSIS
# -------------------------------------------------
def html_intent_score(url):
    try:
        r = requests.get(url, timeout=5)
        html = r.text.lower()

        has_password = "type=\"password\"" in html
        has_login_words = any(
            word in html for word in ["login", "verify", "signin", "password"]
        )

        return 1 if has_password and has_login_words else 0
    except:
        return 0
def numeric_domain_score(url):
    try:
        ext = tldextract.extract(url)
        return 1 if ext.domain.isdigit() else 0
    except:
        return 0
    
    
SUSPICIOUS_TLDS = {
    "login", "verify", "secure", "account", "update", "signin", "bank"
}
def suspicious_tld_score(url):
    try:
        # Fallback TLD extraction (do NOT trust tldextract alone)
        host = url.split("//")[-1].split("/")[0].lower()

        if "." not in host:
            return 0

        tld = host.split(".")[-1]

        if tld in ["login", "verify", "secure", "update", "account", "signin", "bank"]:
            return 1

        return 0
    except:
        return 0




    
    
ACTION_KEYWORDS = {
    "login", "secure", "verify", "account", "update", "signin", "bank"
}

def action_domain_score(url):
    try:
        ext = tldextract.extract(url)
        domain = ext.domain.lower()
        return 1 if any(word in domain for word in ACTION_KEYWORDS) else 0
    except:
        return 0



