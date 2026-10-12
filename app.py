import re
import socket
from urllib.parse import urlparse

import streamlit as st
import pandas as pd
import joblib

from feature_extraction import (
    extract_features,
    FEATURE_NAMES,
    get_hostname,
    is_ip_address
)

from domain_similarity import detect_lookalike_domain


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Phishing Website Detection System",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# LOAD MODEL
# ============================================================

@st.cache_resource
def load_model():

    model = joblib.load("model.pkl")
    feature_names = joblib.load("feature_names.pkl")

    return model, feature_names


try:

    model, model_feature_names = load_model()

except Exception as e:

    st.error("Unable to load the trained model.")
    st.error(str(e))
    st.stop()


# ============================================================
# TRUSTED DOMAINS
# ============================================================

TRUSTED_DOMAINS = {
    "google.com",
    "youtube.com",
    "gmail.com",

    "microsoft.com",
    "outlook.com",

    "apple.com",
    "icloud.com",

    "amazon.com",

    "paypal.com",

    "facebook.com",
    "instagram.com",

    "linkedin.com",

    "github.com",

    "netflix.com",

    "spotify.com",

    "twitter.com",
    "x.com",

    "dropbox.com",

    "adobe.com",

    "steam.com",

    "whatsapp.com",
    "telegram.org"
}


# ============================================================
# TRUSTED BRANDS
# ============================================================

TRUSTED_BRANDS = {
    "google",
    "youtube",
    "gmail",

    "microsoft",
    "outlook",

    "apple",
    "icloud",

    "amazon",

    "paypal",

    "facebook",
    "instagram",

    "linkedin",

    "github",

    "netflix",

    "spotify",

    "twitter",
    "x",

    "dropbox",

    "adobe",

    "steam",

    "whatsapp",
    "telegram"
}


# ============================================================
# SUSPICIOUS DOMAIN WORDS
# ============================================================

SUSPICIOUS_DOMAIN_WORDS = {
    "login",
    "signin",
    "sign-in",
    "secure",
    "security",
    "verify",
    "verification",
    "account",
    "accounts",
    "update",
    "updated",
    "confirm",
    "confirmation",
    "support",
    "service",
    "billing",
    "payment",
    "payments",
    "wallet",
    "authentication",
    "authorize",
    "authorization",
    "recovery",
    "password",
    "credential",
    "credentials"
}


# ============================================================
# NORMALIZE URL
# ============================================================

def normalize_input_url(url):

    url = url.strip()

    if not re.match(
        r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
        url
    ):
        url = "http://" + url

    return url


# ============================================================
# GET HOSTNAME
# ============================================================

def get_clean_hostname(url):

    parsed = urlparse(
        normalize_input_url(url)
    )

    hostname = (
        parsed.hostname or ""
    ).lower().strip().rstrip(".")

    if hostname.startswith("www."):

        hostname = hostname[4:]

    return hostname


# ============================================================
# EXACT TRUSTED DOMAIN CHECK
# ============================================================

def is_exact_trusted_domain(url):

    hostname = get_clean_hostname(url)

    return hostname in TRUSTED_DOMAINS


# ============================================================
# PHISHING KEYWORD DETECTION
# ============================================================

def detect_phishing_keywords(url):

    parsed = urlparse(
        normalize_input_url(url)
    )

    full_url = (
        parsed.geturl()
        .lower()
    )

    found_keywords = []

    for keyword in SUSPICIOUS_DOMAIN_WORDS:

        if keyword in full_url:

            found_keywords.append(
                keyword
            )

    return sorted(
        set(found_keywords)
    )


# ============================================================
# BRAND IMPERSONATION DETECTION
# ============================================================

def detect_brand_impersonation(url):

    hostname = get_clean_hostname(url)

    if not hostname:
        return None


    # ========================================================
    # VERY IMPORTANT:
    # REAL TRUSTED DOMAIN MUST NEVER BE FLAGGED
    # ========================================================

    if hostname in TRUSTED_DOMAINS:

        return None


    # Remove TLD and split domain
    domain_without_tld = hostname.split(".")[0]

    domain_parts = re.split(
        r"[-_]",
        domain_without_tld
    )

    domain_parts = [
        part.lower()
        for part in domain_parts
        if part
    ]


    # ========================================================
    # BRAND + SUSPICIOUS WORD
    # ========================================================

    for brand in TRUSTED_BRANDS:

        if brand not in domain_parts:
            continue


        for part in domain_parts:

            if part == brand:
                continue


            if part in SUSPICIOUS_DOMAIN_WORDS:

                return {
                    "brand": brand,
                    "reason": (
                        f"The trusted brand '{brand}' "
                        f"is combined with the suspicious "
                        f"term '{part}'."
                    )
                }


    # ========================================================
    # BRAND WITH EXTRA TEXT
    # ========================================================

    clean_domain = re.sub(
        r"[^a-z0-9]",
        "",
        domain_without_tld
    )


    for brand in TRUSTED_BRANDS:

        # Exact brand already handled above.
        if clean_domain == brand:
            continue


        # Brand contained inside a longer domain.
        if (
            brand in clean_domain
            and len(clean_domain)
            > len(brand) + 2
        ):

            return {
                "brand": brand,
                "reason": (
                    f"The domain contains the trusted "
                    f"brand name '{brand}' with additional text."
                )
            }


    return None


# ============================================================
# URL STRUCTURE DETECTION
# ============================================================

def detect_url_structure_risks(url):

    parsed = urlparse(
        normalize_input_url(url)
    )

    hostname = (
        parsed.hostname or ""
    ).lower()

    risks = []


    # --------------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------------

    if is_ip_address(hostname):

        risks.append(
            "IP address or numeric hostname detected."
        )


    # --------------------------------------------------------
    # @ SYMBOL
    # --------------------------------------------------------

    if "@" in url:

        risks.append(
            "The URL contains the @ symbol."
        )


    # --------------------------------------------------------
    # VERY LONG URL
    # --------------------------------------------------------

    if len(url) > 100:

        risks.append(
            "Unusually long URL detected."
        )


    # --------------------------------------------------------
    # MANY SUBDOMAINS
    # --------------------------------------------------------

    hostname_parts = hostname.split(".")

    if len(hostname_parts) >= 4:

        risks.append(
            "Unusually large number of subdomains detected."
        )


    # --------------------------------------------------------
    # MULTIPLE HYPHENS
    # --------------------------------------------------------

    if hostname.count("-") >= 2:

        risks.append(
            "Multiple hyphens detected in the hostname."
        )


    # --------------------------------------------------------
    # NON-STANDARD PORT
    # --------------------------------------------------------

    try:

        port = parsed.port

        if port is not None:

            if port not in [80, 443]:

                risks.append(
                    "Non-standard network port detected."
                )

    except Exception:
        pass


    # --------------------------------------------------------
    # SUSPICIOUS DOMAIN WORDS
    # --------------------------------------------------------

    domain_words = re.split(
        r"[.\-_]",
        hostname
    )

    found_words = []

    for word in domain_words:

        if word in SUSPICIOUS_DOMAIN_WORDS:

            found_words.append(word)


    if found_words:

        risks.append(
            "Suspicious security/account-related "
            "term found in domain: "
            + ", ".join(
                sorted(set(found_words))
            )
        )


    return risks


# ============================================================
# DNS CHECK
# ============================================================

def detect_dns_risk(url):

    hostname = get_clean_hostname(url)

    if not hostname:

        return [
            "Invalid hostname."
        ]


    # Do not treat a genuine trusted domain as suspicious
    # merely because of DNS behavior.
    try:

        socket.gethostbyname(hostname)

        return []

    except Exception:

        return [
            "Hostname could not be resolved through DNS."
        ]


# ============================================================
# FINAL SECURITY VERDICT
# ============================================================

def calculate_security_verdict(
    model_prediction,
    url,
    lookalike_result
):

    reasons = []

    score = 0


    # ========================================================
    # EXACT TRUSTED DOMAIN
    # ========================================================

    if is_exact_trusted_domain(url):

        return (
            "LEGITIMATE",
            0,
            []
        )


    # ========================================================
    # RANDOM FOREST
    # ========================================================

    if int(model_prediction) == 1:

        score += 4

        reasons.append(
            "Random Forest model classified the URL as phishing."
        )


    # ========================================================
    # LOOKALIKE DOMAIN
    # ========================================================

    if lookalike_result.get(
        "suspicious"
    ):

        score += 5

        matched_domain = (
            lookalike_result.get(
                "matched_domain"
            )
        )

        if matched_domain:

            reasons.append(
                "Possible lookalike domain detected "
                f"(similar to {matched_domain})."
            )

        else:

            reasons.append(
                "Possible lookalike domain detected."
            )


    # ========================================================
    # BRAND IMPERSONATION
    # ========================================================

    brand_result = detect_brand_impersonation(
        url
    )

    if brand_result:

        score += 5

        reasons.append(
            brand_result["reason"]
        )


    # ========================================================
    # URL STRUCTURE
    # ========================================================

    structure_risks = detect_url_structure_risks(
        url
    )

    for risk in structure_risks:

        score += 1

        reasons.append(risk)


    # ========================================================
    # PHISHING KEYWORDS
    # ========================================================

    keywords = detect_phishing_keywords(
        url
    )

    if keywords:

        score += min(
            len(keywords),
            3
        )

        reasons.append(
            "Phishing-related keyword(s) detected: "
            + ", ".join(keywords)
        )


    # ========================================================
    # DNS
    # ========================================================

    dns_risks = detect_dns_risk(
        url
    )

    for risk in dns_risks:

        score += 1

        reasons.append(risk)


    # ========================================================
    # FINAL DECISION
    # ========================================================

    if score >= 5:

        verdict = "PHISHING"

    elif score >= 3:

        verdict = "SUSPICIOUS"

    else:

        verdict = "LEGITIMATE"


    return (
        verdict,
        score,
        list(dict.fromkeys(reasons))
    )


# ============================================================
# USER INTERFACE
# ============================================================

st.title(
    "🛡️ Phishing Website Detection System"
)

st.write(
    "Enter a website URL to check whether it contains "
    "characteristics commonly associated with phishing."
)


# ============================================================
# URL INPUT
# ============================================================

url = st.text_input(
    "🌐 Enter Website URL",
    placeholder="Example: https://example.com"
)


# ============================================================
# ANALYZE BUTTON
# ============================================================

if st.button(
    "🔍 Analyze Website",
    use_container_width=True
):

    if not url.strip():

        st.warning(
            "Please enter a website URL."
        )

        st.stop()


    try:

        # ====================================================
        # NORMALIZE
        # ====================================================

        entered_url = normalize_input_url(
            url
        )


        parsed = urlparse(
            entered_url
        )


        if not parsed.hostname:

            st.error(
                "Invalid URL. Please enter a valid website."
            )

            st.stop()


        # ====================================================
        # FEATURE EXTRACTION
        # ====================================================

        with st.spinner(
            "Analyzing website..."
        ):

            feature_values = extract_features(
                entered_url
            )


        if len(feature_values) != 30:

            st.error(
                "Feature extraction failed. "
                f"Expected 30 features but received "
                f"{len(feature_values)}."
            )

            st.stop()


        st.success(
            "Successfully extracted 30 features."
        )


        # ====================================================
        # MODEL INPUT
        # ====================================================

        input_data = pd.DataFrame(
            [feature_values],
            columns=FEATURE_NAMES
        )


        expected_features = list(
            model_feature_names
        )


        missing_features = [
            feature
            for feature in expected_features
            if feature not in input_data.columns
        ]


        if missing_features:

            st.error(
                "Missing model features: "
                + ", ".join(
                    missing_features
                )
            )

            st.stop()


        input_data = input_data[
            expected_features
        ]


        # ====================================================
        # RANDOM FOREST PREDICTION
        # ====================================================

        model_prediction = model.predict(
            input_data
        )[0]


        # ====================================================
        # LOOKALIKE CHECK
        # ====================================================

        lookalike_result = (
            detect_lookalike_domain(
                entered_url
            )
        )


        # ====================================================
        # FINAL VERDICT
        # ====================================================

        (
            final_verdict,
            security_score,
            reasons
        ) = calculate_security_verdict(
            model_prediction,
            entered_url,
            lookalike_result
        )


        # ====================================================
        # FINAL RESULT
        # ====================================================

        st.divider()

        st.subheader(
            "📊 Final Security Result"
        )


        if final_verdict == "PHISHING":

            st.error(
                "🚨 PHISHING WEBSITE"
            )

            st.write(
                "This URL has been identified as potentially "
                "phishing based on the combined security analysis."
            )


        elif final_verdict == "SUSPICIOUS":

            st.warning(
                "⚠️ SUSPICIOUS WEBSITE"
            )

            st.write(
                "This URL contains suspicious characteristics "
                "and should be treated with caution."
            )


        else:

            st.success(
                "✅ LEGITIMATE WEBSITE"
            )

            st.write(
                "No strong phishing indicators were detected."
            )


        # ====================================================
        # DETECTION REASONS
        # ====================================================

        if reasons:

            st.write(
                "### 🔎 Detection Reasons"
            )

            for reason in reasons:

                st.write(
                    "• " + reason
                )


        # ====================================================
        # MACHINE LEARNING RESULT
        # ====================================================

        with st.expander(
            "🤖 View Machine Learning Result"
        ):

            if int(model_prediction) == 1:

                st.write(
                    "Random Forest: **PHISHING**"
                )

            else:

                st.write(
                    "Random Forest: **LEGITIMATE**"
                )


        # ====================================================
        # LOOKALIKE DETAILS
        # ====================================================

        if lookalike_result.get(
            "suspicious"
        ):

            st.write(
                "### 🎭 Lookalike Domain Detection"
            )

            col1, col2, col3 = st.columns(3)


            with col1:

                st.write(
                    "**Entered Domain**"
                )

                st.code(
                    lookalike_result.get(
                        "domain",
                        "Unknown"
                    )
                )


            with col2:

                st.write(
                    "**Similar Trusted Domain**"
                )

                st.code(
                    lookalike_result.get(
                        "matched_domain",
                        "Unknown"
                    )
                )


            with col3:

                similarity = (
                    lookalike_result.get(
                        "similarity",
                        0
                    )
                )

                st.write(
                    "**Similarity**"
                )

                st.write(
                    f"{similarity * 100:.2f}%"
                )


        # ====================================================
        # URL DISPLAY
        # ====================================================

        st.divider()

        st.subheader(
            "🌐 URL Analyzed"
        )

        st.code(
            entered_url
        )


        # ====================================================
        # FEATURES
        # ====================================================

        with st.expander(
            "🔬 View Extracted Features"
        ):

            feature_table = pd.DataFrame(
                {
                    "Feature": FEATURE_NAMES,
                    "Value": feature_values
                }
            )

            st.dataframe(
                feature_table,
                use_container_width=True,
                hide_index=True
            )


    except Exception as e:

        st.error(
            "An error occurred while analyzing the URL."
        )

        st.exception(e)