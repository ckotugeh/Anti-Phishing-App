"""
detector.py — Multi-signal phishing URL detector.

Analyses a URL across multiple heuristic signals and returns a structured
result with a confidence score, verdict, and list of findings.
"""

import re
from urllib.parse import urlparse, parse_qs
from typing import NamedTuple


# Signal weights (sum to 1.0)

_WEIGHTS = {
    "suspicious_keywords": 0.25,
    "suspicious_tld":      0.15,
    "ip_in_url":           0.15,
    "url_shortener":       0.10,
    "excessive_subdomains": 0.10,
    "homoglyph":           0.10,
    "long_url":            0.05,
    "query_sensitive_keys": 0.10,
}


# Reference data

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "update", "secure",
    "bank", "webscr", "paypal", "appleid", "icloud",
    "microsoft", "google", "amazon", "netflix", "ebay",
    "irs", "gov", "security", "alert", "suspended",
    "limited", "urgent", "immediate", "confirm",
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".gq", ".cf", ".tk", ".ml",
    ".ga", ".pw", ".cc", ".club", ".click", ".loan",
    ".win", ".bid", ".trade", ".date", ".review",
]

URL_SHORTENERS = [
    "bit.ly", "goo.gl", "tinyurl.com", "ow.ly",
    "t.co", "is.gd", "buff.ly", "adf.ly", "bitly.com",
    "shorte.st", "bc.vc", "click.me", "db.tt",
]

SENSITIVE_QUERY_KEYS = [
    "password", "pass", "token", "key", "secret",
    "session", "auth", "access_token", "api_key",
    "credit", "card", "cvv", "ssn",
]

# Approximate ASCII look-alikes for common Latin characters
HOMOGLYPH_MAP = {
    'a': 'а', 'e': 'е', 'o': 'о', 'p': 'р',
    'c': 'с', 'x': 'х', 'y': 'у', 'b': 'ь',
    'h': 'ջ', 'i': 'і',
}

# Helpers

def _extract_domain(parsed: "ParseResult") -> str:
    """Return the registered domain (netloc without port)."""
    return parsed.hostname or ""


def _count_subdomains(domain: str) -> int:
    """Number of dot-separated labels minus the registered part (≥0)."""
    return max(domain.count(".") - 1, 0)


def _has_ip_address(domain: str) -> bool:
    """True if the hostname looks like an IPv4 address."""
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain))


def _detect_homoglyphs(url: str) -> list[str]:
    """Return list of (original_char, replacement_char) pairs found."""
    found = []
    for original, replacement in HOMOGLYPH_MAP.items():
        if replacement in url.lower():
            found.append(f"{original}→{replacement}")
    return found


# Core scoring

class SignalResult(NamedTuple):
    name: str
    score: float          # 0.0 – 1.0
    detail: str


def _score_suspicious_keywords(url: str) -> SignalResult:
    lower = url.lower()
    hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower]
    score = min(len(hits) * 0.125, 1.0) if hits else 0.0
    return SignalResult("suspicious_keywords", score,
                        f"matched keywords: {hits}" if hits else "no match")


def _extract_tld(hostname: str) -> str:
    """Return the last two dot-separated parts of a hostname as the TLD."""
    parts = hostname.split(".")
    return "." + ".".join(parts[-2:]) if len(parts) >= 2 else ""


def _score_suspicious_tld(parsed: "ParseResult") -> SignalResult:
    tld = _extract_tld(parsed.hostname or "").lower()
    if tld in SUSPICIOUS_TLDS:
        return SignalResult("suspicious_tld", 1.0, f"suspicious TLD: {tld}")
    return SignalResult("suspicious_tld", 0.0, f"TLD: {tld or 'none'}")


def _score_ip_in_url(parsed: "ParseResult") -> SignalResult:
    if _has_ip_address(parsed.hostname or ""):
        return SignalResult("ip_in_url", 1.0, "URL uses IP address instead of domain")
    return SignalResult("ip_in_url", 0.0, "hostname is a domain name")


def _score_url_shortener(parsed: "ParseResult") -> SignalResult:
    host = (parsed.hostname or "").lower()
    if any(short in host for short in URL_SHORTENERS):
        return SignalResult("url_shortener", 1.0, "URL uses a known shortener")
    return SignalResult("url_shortener", 0.0, "not a URL shortener")


def _score_excessive_subdomains(parsed: "ParseResult") -> SignalResult:
    sub_count = _count_subdomains(parsed.hostname or "")
    if sub_count >= 3:
        return SignalResult("excessive_subdomains", min(sub_count * 0.25, 1.0),
                            f"{sub_count} subdomain levels detected")
    return SignalResult("excessive_subdomains", 0.0,
                        f"{sub_count} subdomain levels")


def _score_homoglyphs(url: str) -> SignalResult:
    found = _detect_homoglyphs(url)
    score = min(len(found) * 0.5, 1.0) if found else 0.0
    return SignalResult("homoglyph", score,
                        f"homoglyphs: {found}" if found else "no homoglyphs")


def _score_long_url(url: str) -> SignalResult:
    length = len(url)
    if length > 2048:
        return SignalResult("long_url", 1.0, f"URL length {length} > 2048")
    if length > 500:
        return SignalResult("long_url", 0.5, f"URL length {length} > 500")
    return SignalResult("long_url", 0.0, f"URL length {length}")


def _score_query_sensitive_keys(parsed: "ParseResult") -> SignalResult:
    qs = parse_qs(parsed.query)
    hits = [k for k in qs if k.lower() in SENSITIVE_QUERY_KEYS]
    score = min(len(hits) * 0.35, 1.0) if hits else 0.0
    return SignalResult("query_sensitive_keys", score,
                        f"sensitive query params: {hits}" if hits else "no sensitive params")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyse_url(url: str) -> dict:
    """
    Analyse *url* and return a dict with:

    {
        "url": str,
        "verdict": "safe" | "suspicious" | "phishing",
        "confidence": float,          # 0.0 – 1.0
        "signals": [SignalResult…],
        "recommendation": str,
    }
    """
    # Validate URL shape
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        return {
            "url": url,
            "verdict": "error",
            "confidence": 0.0,
            "signals": [],
            "recommendation": "Could not parse the supplied URL.",
        }

    if not parsed.hostname:
        return {
            "url": url,
            "verdict": "error",
            "confidence": 0.0,
            "signals": [],
            "recommendation": "URL has no valid hostname.",
        }

    # Run every signal
    signals: list[SignalResult] = [
        _score_suspicious_keywords(url),
        _score_suspicious_tld(parsed),
        _score_ip_in_url(parsed),
        _score_url_shortener(parsed),
        _score_excessive_subdomains(parsed),
        _score_homoglyphs(url),
        _score_long_url(url),
        _score_query_sensitive_keys(parsed),
    ]

    # Weighted confidence
    confidence = sum(s.score * _WEIGHTS[s.name] for s in signals)

    # Verdict thresholds
    if confidence >= 0.60:
        verdict = "phishing"
    elif confidence >= 0.30:
        verdict = "suspicious"
    else:
        verdict = "safe"

    # Human-readable recommendation
    if verdict == "phishing":
        recommendation = "Block this URL — high phishing risk."
    elif verdict == "suspicious":
        recommendation = "Proceed with caution — review signals below."
    else:
        recommendation = "URL appears safe."

    return {
        "url": url,
        "verdict": verdict,
        "confidence": round(confidence, 4),
        "signals": [
            {"name": s.name, "score": s.score, "detail": s.detail}
            for s in signals
        ],
        "recommendation": recommendation,
    }
