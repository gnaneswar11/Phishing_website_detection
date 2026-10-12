import re
import socket
import ipaddress
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup


# ============================================================
# URL / HOSTNAME HELPERS
# ============================================================

def normalize_url(url):
    url = url.strip()

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url

    return url


def get_hostname(url):
    try:
        parsed = urlparse(normalize_url(url))
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def is_ip_address(hostname):
    """
    Detect normal IP addresses as well as incomplete/dotted
    numeric hostnames such as 192.168.1.
    """
    if not hostname:
        return False

    hostname = hostname.strip().lower().rstrip(".")

    # Normal IPv4 / IPv6
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass

    # Detect dotted numeric hostnames such as:
    # 192.168.1
    # 192.168.1.10
    parts = hostname.split(".")

    if 2 <= len(parts) <= 4 and all(
        part.isdigit() and 0 <= int(part) <= 255
        for part in parts
    ):
        return True

    return False


# ============================================================
# 1. UsingIP
# ============================================================

def extract_using_ip(url):
    hostname = get_hostname(url)

    if is_ip_address(hostname):
        return -1

    return 1


# ============================================================
# 2. LongURL
# ============================================================

def extract_long_url(url):
    length = len(url)

    if length < 54:
        return 1
    elif length <= 75:
        return 0
    else:
        return -1


# ============================================================
# 3. ShortURL
# ============================================================

def extract_short_url(url):
    shorteners = [
        "bit.ly",
        "goo.gl",
        "tinyurl.com",
        "t.co",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "adf.ly",
        "bit.do",
        "cutt.ly",
        "tiny.cc",
        "lnkd.in",
        "shorturl.at",
        "rebrand.ly"
    ]

    hostname = get_hostname(url)

    for service in shorteners:
        if hostname == service or hostname.endswith("." + service):
            return -1

    return 1


# ============================================================
# 4. Symbol@
# ============================================================

def extract_symbol_at(url):
    return -1 if "@" in url else 1


# ============================================================
# 5. Redirecting//
# ============================================================

def extract_redirecting(url):
    try:
        parsed = urlparse(normalize_url(url))

        after_scheme = parsed.path

        if "//" in after_scheme:
            return -1

        return 1

    except Exception:
        return 1


# ============================================================
# 6. PrefixSuffix-
# ============================================================

def extract_prefix_suffix(url):
    hostname = get_hostname(url)

    return -1 if "-" in hostname else 1


# ============================================================
# 7. SubDomains
# ============================================================

def extract_subdomains(url):
    hostname = get_hostname(url)

    if not hostname:
        return -1

    if is_ip_address(hostname):
        return -1

    parts = hostname.split(".")

    # Remove empty parts
    parts = [p for p in parts if p]

    # Basic domain structure
    if len(parts) <= 2:
        return 1
    elif len(parts) == 3:
        return 0
    else:
        return -1


# ============================================================
# 8. HTTPS
# ============================================================

def extract_https(url):
    try:
        parsed = urlparse(normalize_url(url))

        if parsed.scheme.lower() == "https":
            return 1

        return -1

    except Exception:
        return -1


# ============================================================
# 9. DomainRegLen
# ============================================================

def extract_domain_reg_len(url):
    """
    WHOIS-based registration length.

    Returns only values allowed by the dataset:
    1  = acceptable
    -1 = suspicious
    """

    try:
        import whois

        hostname = get_hostname(url)

        if not hostname or is_ip_address(hostname):
            return -1

        data = whois.whois(hostname)

        creation_date = data.creation_date
        expiration_date = data.expiration_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        if creation_date and expiration_date:
            days = (expiration_date - creation_date).days

            if days >= 365:
                return 1
            else:
                return -1

    except Exception:
        pass

    # Conservative fallback
    return -1


# ============================================================
# 10. Favicon
# ============================================================

def extract_favicon(soup, url):
    try:
        if soup is None:
            return -1

        hostname = get_hostname(url)

        for link in soup.find_all("link"):
            rel = link.get("rel", [])

            if isinstance(rel, str):
                rel = [rel]

            rel_text = " ".join(rel).lower()

            if "icon" in rel_text:
                href = link.get("href", "")

                if not href:
                    return -1

                parsed_icon = urlparse(href)

                # Relative favicon
                if not parsed_icon.netloc:
                    return 1

                icon_host = parsed_icon.hostname or ""

                if icon_host == hostname:
                    return 1

                return -1

        return -1

    except Exception:
        return -1


# ============================================================
# 11. NonStdPort
# ============================================================

def extract_non_std_port(url):
    try:
        parsed = urlparse(normalize_url(url))

        if parsed.port is None:
            return 1

        if parsed.scheme.lower() == "http" and parsed.port == 80:
            return 1

        if parsed.scheme.lower() == "https" and parsed.port == 443:
            return 1

        return -1

    except Exception:
        return -1


# ============================================================
# 12. HTTPSDomainURL
# ============================================================

def extract_https_domain_url(url):
    hostname = get_hostname(url)

    if "https" in hostname:
        return -1

    return 1


# ============================================================
# PAGE REQUEST
# ============================================================

def _is_public_http_url(url):
    """Allow only HTTP(S) URLs resolving exclusively to public IPs."""
    try:
        parsed = urlparse(normalize_url(url))
        if parsed.scheme.lower() not in {"http", "https"}:
            return False
        if not parsed.hostname or parsed.username or parsed.password:
            return False
        hostname = parsed.hostname.rstrip(".").lower()
        if hostname == "localhost" or hostname.endswith(".localhost") or hostname.endswith(".local"):
            return False
        try:
            literal_ip = ipaddress.ip_address(hostname)
            return literal_ip.is_global
        except ValueError:
            pass
        records = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme.lower() == "https" else 80), type=socket.SOCK_STREAM)
        addresses = {record[4][0].split("%", 1)[0] for record in records}
        return bool(addresses) and all(ipaddress.ip_address(addr).is_global for addr in addresses)
    except Exception:
        return False


def get_page(url):
    """Fetch a public page safely; validate every redirect target."""
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
        )
    }
    current_url = normalize_url(url)
    history = []
    try:
        for _ in range(6):
            if not _is_public_http_url(current_url):
                return None
            response = requests.get(
                current_url,
                headers=headers,
                timeout=8,
                allow_redirects=False,
                verify=True,
                stream=False,
            )
            if response.status_code not in {301, 302, 303, 307, 308}:
                response.history = history
                return response
            location = response.headers.get("Location")
            if not location:
                response.history = history
                return response
            history.append(response)
            from urllib.parse import urljoin
            current_url = urljoin(current_url, location)
        return None
    except (requests.RequestException, ValueError, OSError):
        return None


# ============================================================
# 13. RequestURL
# ============================================================

def extract_request_url(soup, url):
    try:
        if soup is None:
            return -1

        hostname = get_hostname(url)

        resources = []

        for tag in soup.find_all(["img", "audio", "video", "embed", "object"]):

            attribute = tag.get("src") or tag.get("data")

            if attribute:
                resources.append(attribute)

        if not resources:
            return 1

        external = 0

        for resource in resources:
            parsed = urlparse(resource)

            if parsed.netloc:
                resource_host = parsed.hostname or ""

                if resource_host != hostname:
                    external += 1

        ratio = external / len(resources)

        # Dataset uses binary values for RequestURL.
        if ratio < 0.22:
            return 1

        return -1

    except Exception:
        return -1


# ============================================================
# 14. AnchorURL
# ============================================================

def extract_anchor_url(soup, url):
    try:
        if soup is None:
            return -1

        hostname = get_hostname(url)

        anchors = soup.find_all("a")

        if not anchors:
            return 1

        suspicious = 0

        for anchor in anchors:
            href = anchor.get("href")

            if not href:
                suspicious += 1
                continue

            href_lower = href.lower().strip()

            if href_lower.startswith("#"):
                suspicious += 1
                continue

            if href_lower.startswith("javascript:"):
                suspicious += 1
                continue

            parsed = urlparse(href)

            if parsed.netloc:
                anchor_host = parsed.hostname or ""

                if anchor_host != hostname:
                    suspicious += 1

        ratio = suspicious / len(anchors)

        if ratio < 0.31:
            return 1
        elif ratio < 0.67:
            return 0
        else:
            return -1

    except Exception:
        return -1


# ============================================================
# 15. LinksInScriptTags
# ============================================================

def extract_links_in_script_tags(soup, url):
    try:
        if soup is None:
            return -1

        hostname = get_hostname(url)

        scripts = soup.find_all("script")

        if not scripts:
            return 1

        external = 0

        for script in scripts:
            src = script.get("src")

            if src:
                parsed = urlparse(src)

                if parsed.netloc:
                    script_host = parsed.hostname or ""

                    if script_host != hostname:
                        external += 1

        ratio = external / len(scripts)

        if ratio < 0.17:
            return 1
        elif ratio < 0.81:
            return 0
        else:
            return -1

    except Exception:
        return -1


# ============================================================
# 16. ServerFormHandler
# ============================================================

def extract_server_form_handler(soup, url):
    try:
        if soup is None:
            return -1

        hostname = get_hostname(url)

        forms = soup.find_all("form")

        if not forms:
            return 1

        for form in forms:

            action = form.get("action")

            if action is None or action == "":
                return 0

            parsed = urlparse(action)

            if parsed.netloc:
                form_host = parsed.hostname or ""

                if form_host != hostname:
                    return -1

        return 1

    except Exception:
        return -1


# ============================================================
# 17. InfoEmail
# ============================================================

def extract_info_email(soup):
    try:
        if soup is None:
            return 1

        page_text = soup.get_text(" ", strip=True).lower()

        if "mailto:" in str(soup).lower():
            return -1

        if re.search(
            r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
            page_text
        ):
            return -1

        return 1

    except Exception:
        return 1


# ============================================================
# 18. AbnormalURL
# ============================================================

def extract_abnormal_url(url):
    try:
        hostname = get_hostname(url)

        if not hostname:
            return -1

        # IP-based hostname
        if is_ip_address(hostname):
            return -1

        parsed = urlparse(normalize_url(url))

        if parsed.netloc:
            return 1

        return -1

    except Exception:
        return -1


# ============================================================
# 19. WebsiteForwarding
# ============================================================

def extract_website_forwarding(url, response=None):
    try:
        if response is None:
            response = get_page(url)

        if response is None:
            return 0

        redirects = len(response.history)

        # Dataset allowed values: 0, 1
        if redirects <= 1:
            return 1

        return 0

    except Exception:
        return 0


# ============================================================
# 20. StatusBarCust
# ============================================================

def extract_status_bar_cust(soup):
    try:
        if soup is None:
            return 1

        html = str(soup).lower()

        suspicious_patterns = [
            "onmouseover",
            "window.status",
            "status="
        ]

        for pattern in suspicious_patterns:
            if pattern in html:
                return -1

        return 1

    except Exception:
        return 1


# ============================================================
# 21. DisableRightClick
# ============================================================

def extract_disable_right_click(soup):
    try:
        if soup is None:
            return 1

        html = str(soup).lower()

        if (
            "contextmenu" in html
            or "event.button==2" in html
            or "event.button == 2" in html
        ):
            return -1

        return 1

    except Exception:
        return 1


# ============================================================
# 22. UsingPopupWindow
# ============================================================

def extract_using_popup_window(soup):
    try:
        if soup is None:
            return 1

        html = str(soup).lower()

        if "window.open(" in html:
            return -1

        return 1

    except Exception:
        return 1


# ============================================================
# 23. IframeRedirection
# ============================================================

def extract_iframe_redirection(soup):
    try:
        if soup is None:
            return 1

        iframes = soup.find_all("iframe")

        if not iframes:
            return 1

        for iframe in iframes:
            src = iframe.get("src")

            if src:
                parsed = urlparse(src)

                if parsed.netloc:
                    return -1

        return 1

    except Exception:
        return 1


# ============================================================
# 24. AgeofDomain
# ============================================================

def extract_age_of_domain(url):
    try:
        import whois

        hostname = get_hostname(url)

        if not hostname or is_ip_address(hostname):
            return -1

        data = whois.whois(hostname)

        creation_date = data.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return -1

        from datetime import datetime

        age_days = (datetime.now() - creation_date).days

        if age_days >= 180:
            return 1

        return -1

    except Exception:
        return -1


# ============================================================
# 25. DNSRecording
# ============================================================

def extract_dns_recording(url):
    try:
        hostname = get_hostname(url)

        if not hostname or is_ip_address(hostname):
            return -1

        socket.gethostbyname(hostname)

        return 1

    except Exception:
        return -1


# ============================================================
# 26. WebsiteTraffic
# ============================================================

def extract_website_traffic(url):
    """
    Historical dataset feature.

    Since the original dataset depends on historical external
    traffic information, a live equivalent is not always
    available. Conservative value is used when live data
    cannot be obtained.
    """

    hostname = get_hostname(url)

    if not hostname:
        return -1

    # IP-based URLs are treated as suspicious.
    if is_ip_address(hostname):
        return -1

    # No reliable live traffic API is used here.
    return 0


# ============================================================
# 27. PageRank
# ============================================================

def extract_page_rank(url):
    """
    Historical PageRank values are no longer directly available
    from the old public service.

    Conservative fallback.
    """

    hostname = get_hostname(url)

    if not hostname:
        return -1

    return 1


# ============================================================
# 28. GoogleIndex
# ============================================================

def extract_google_index(url):
    """
    Google indexing cannot be reliably determined by directly
    scraping Google from the application.

    Conservative fallback.
    """

    hostname = get_hostname(url)

    if not hostname:
        return -1

    return 1


# ============================================================
# 29. LinksPointingToPage
# ============================================================

def extract_links_pointing_to_page(url):
    """
    Historical external backlink feature.

    Exact historical backlink count cannot be reconstructed
    reliably from the URL alone.
    """

    hostname = get_hostname(url)

    if not hostname:
        return -1

    return 0


# ============================================================
# 30. StatsReport
# ============================================================

def extract_stats_report(url):
    """
    Historical blacklist/statistics feature.

    External historical services are not queried here.
    """

    hostname = get_hostname(url)

    if not hostname:
        return -1

    return 1


# ============================================================
# MAIN FEATURE EXTRACTION
# ============================================================

FEATURE_NAMES = [
    "UsingIP",
    "LongURL",
    "ShortURL",
    "Symbol@",
    "Redirecting//",
    "PrefixSuffix-",
    "SubDomains",
    "HTTPS",
    "DomainRegLen",
    "Favicon",
    "NonStdPort",
    "HTTPSDomainURL",
    "RequestURL",
    "AnchorURL",
    "LinksInScriptTags",
    "ServerFormHandler",
    "InfoEmail",
    "AbnormalURL",
    "WebsiteForwarding",
    "StatusBarCust",
    "DisableRightClick",
    "UsingPopupWindow",
    "IframeRedirection",
    "AgeofDomain",
    "DNSRecording",
    "WebsiteTraffic",
    "PageRank",
    "GoogleIndex",
    "LinksPointingToPage",
    "StatsReport"
]


def extract_features(url):
    url = normalize_url(url)

    print("Extracting features from:", url)

    response = get_page(url)

    soup = None

    if response is not None:
        try:
            soup = BeautifulSoup(response.text, "html.parser")
        except Exception:
            soup = None

    features = {
        "UsingIP": extract_using_ip(url),
        "LongURL": extract_long_url(url),
        "ShortURL": extract_short_url(url),
        "Symbol@": extract_symbol_at(url),
        "Redirecting//": extract_redirecting(url),
        "PrefixSuffix-": extract_prefix_suffix(url),
        "SubDomains": extract_subdomains(url),
        "HTTPS": extract_https(url),
        "DomainRegLen": extract_domain_reg_len(url),
        "Favicon": extract_favicon(soup, url),
        "NonStdPort": extract_non_std_port(url),
        "HTTPSDomainURL": extract_https_domain_url(url),
        "RequestURL": extract_request_url(soup, url),
        "AnchorURL": extract_anchor_url(soup, url),
        "LinksInScriptTags": extract_links_in_script_tags(soup, url),
        "ServerFormHandler": extract_server_form_handler(soup, url),
        "InfoEmail": extract_info_email(soup),
        "AbnormalURL": extract_abnormal_url(url),
        "WebsiteForwarding": extract_website_forwarding(url, response),
        "StatusBarCust": extract_status_bar_cust(soup),
        "DisableRightClick": extract_disable_right_click(soup),
        "UsingPopupWindow": extract_using_popup_window(soup),
        "IframeRedirection": extract_iframe_redirection(soup),
        "AgeofDomain": extract_age_of_domain(url),
        "DNSRecording": extract_dns_recording(url),
        "WebsiteTraffic": extract_website_traffic(url),
        "PageRank": extract_page_rank(url),
        "GoogleIndex": extract_google_index(url),
        "LinksPointingToPage": extract_links_pointing_to_page(url),
        "StatsReport": extract_stats_report(url)
    }

    # Ensure exact feature order
    return [features[name] for name in FEATURE_NAMES]