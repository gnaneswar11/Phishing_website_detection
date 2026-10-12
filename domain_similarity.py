import re
from difflib import SequenceMatcher
from urllib.parse import urlparse

TRUSTED_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
    "facebook.com", "instagram.com", "linkedin.com", "github.com", "youtube.com",
    "netflix.com", "wikipedia.org", "twitter.com", "x.com", "gmail.com",
    "outlook.com", "icloud.com", "dropbox.com", "adobe.com", "spotify.com",
    "steam.com", "whatsapp.com", "telegram.org",
}

SUSPICIOUS_WORDS = {
    "login", "signin", "support", "secure", "security", "verify", "verification",
    "account", "update", "confirm", "authentication", "service", "help", "billing",
    "payment", "wallet", "customer", "official", "password", "recovery",
}

# Common multi-label public suffixes. This is a practical fallback, not a complete PSL.
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.in", "firm.in", "net.in", "org.in", "gen.in", "ind.in", "com.br",
    "com.cn", "com.sg", "co.nz", "co.jp", "com.mx", "co.za",
}

def normalize_domain(domain):
    domain = (domain or "").lower().strip().rstrip(".")
    return domain[4:] if domain.startswith("www.") else domain

def clean_domain(domain):
    # Normalize common digit substitutions used in lookalike domains.
    value = re.sub(r"[^a-z0-9]", "", (domain or "").lower())
    return value.translate(str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t"}))

def calculate_similarity(domain1, domain2):
    return SequenceMatcher(None, clean_domain(domain1), clean_domain(domain2)).ratio()

def _hostname_from_url(url):
    candidate = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
        candidate = "http://" + candidate
    return (urlparse(candidate).hostname or "").lower().rstrip(".")

def _registrable_domain(hostname):
    labels = hostname.split(".")
    if len(labels) < 2:
        return ""
    suffix2 = ".".join(labels[-2:])
    if suffix2 in MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return suffix2

def contains_suspicious_word(domain):
    for word in re.split(r"[-_.]", (domain or "").lower()):
        if word in SUSPICIOUS_WORDS:
            return True, word
    return False, None

def detect_lookalike_domain(url):
    try:
        hostname = _hostname_from_url(url)
        current_domain = normalize_domain(_registrable_domain(hostname))
        if not current_domain:
            return {"suspicious": False, "domain": hostname, "matched_domain": None, "similarity": 0.0, "reason": None}
        if current_domain in TRUSTED_DOMAINS:
            return {"suspicious": False, "domain": current_domain, "matched_domain": None, "similarity": 1.0, "reason": None}

        best_match, best_similarity, best_reason = None, 0.0, None
        labels = re.split(r"[-_.]", hostname)
        for trusted in TRUSTED_DOMAINS:
            brand = trusted.split(".")[0]
            similarity = calculate_similarity(current_domain, trusted)
            if similarity > best_similarity:
                best_match, best_similarity, best_reason = trusted, similarity, "High domain similarity"
            suspicious_word, word = contains_suspicious_word(hostname)
            if brand in labels and suspicious_word:
                best_match = trusted
                best_similarity = max(best_similarity, 0.90)
                best_reason = f"Trusted brand combined with suspicious word '{word}'"
            # Flag brand-containing registrable domains such as paypal-login.example.com
            if brand in labels and current_domain != trusted:
                best_match = trusted
                best_similarity = max(best_similarity, 0.80)
                if best_reason is None or best_reason == "High domain similarity":
                    best_reason = "Trusted brand name used with additional domain text"

        suspicious = best_match is not None and (best_similarity >= 0.85 or best_reason != "High domain similarity")
        return {"suspicious": suspicious, "domain": current_domain, "matched_domain": best_match, "similarity": round(best_similarity, 3), "reason": best_reason}
    except Exception:
        return {"suspicious": False, "domain": "", "matched_domain": None, "similarity": 0.0, "reason": None}
