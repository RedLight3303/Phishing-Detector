"""
Phishing URL Detector
Analyzes URLs for common phishing indicators using heuristic feature extraction.
"""

import re
import sys
import math
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Tuple


SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "secure", "update", "confirm",
    "banking", "paypal", "amazon", "apple", "microsoft", "google", "netflix",
    "password", "credential", "wallet", "support", "alert", "urgent"
]

TRUSTED_TLDS = {".com", ".org", ".net", ".edu", ".gov"}
SUSPICIOUS_TLDS = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click", ".link"}

KNOWN_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "netflix",
    "facebook", "instagram", "twitter", "bank", "chase", "wellsfargo"
]


@dataclass
class URLFeatures:
    url: str
    length: int = 0
    num_dots: int = 0
    num_hyphens: int = 0
    num_digits: int = 0
    num_special: int = 0
    has_ip: bool = False
    has_https: bool = False
    has_at_symbol: bool = False
    has_double_slash: bool = False
    subdomain_depth: int = 0
    suspicious_keywords: List[str] = field(default_factory=list)
    brand_in_subdomain: List[str] = field(default_factory=list)
    tld: str = ""
    entropy: float = 0.0
    path_length: int = 0
    num_params: int = 0


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())


def extract_features(url: str) -> URLFeatures:
    f = URLFeatures(url=url)
    f.length = len(url)

    try:
        parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    except Exception:
        return f

    f.has_https = parsed.scheme == "https"
    f.has_at_symbol = "@" in url
    f.has_double_slash = "//" in parsed.path

    netloc = parsed.netloc or ""
    path = parsed.path or ""

    # IP address check
    f.has_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", netloc))

    # Dots, hyphens, digits, special chars
    f.num_dots = url.count(".")
    f.num_hyphens = url.count("-")
    f.num_digits = sum(c.isdigit() for c in netloc)
    f.num_special = sum(c in "!#$%&'*+/=?^`{|}~" for c in url)

    # TLD
    parts = netloc.split(".")
    f.tld = "." + parts[-1] if len(parts) > 1 else ""

    # Subdomain depth (anything beyond domain + TLD)
    if len(parts) > 2:
        f.subdomain_depth = len(parts) - 2
        subdomains = ".".join(parts[:-2]).lower()
        for brand in KNOWN_BRANDS:
            if brand in subdomains:
                f.brand_in_subdomain.append(brand)

    # Suspicious keywords in full URL
    url_lower = url.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in url_lower:
            f.suspicious_keywords.append(kw)

    # Path & params
    f.path_length = len(path)
    f.num_params = len(urllib.parse.parse_qs(parsed.query))

    # Entropy of the domain
    domain = parts[-2] if len(parts) >= 2 else netloc
    f.entropy = shannon_entropy(domain)

    return f


def score_url(f: URLFeatures) -> Tuple[int, List[str]]:
    score = 0
    reasons = []

    if f.has_ip:
        score += 30
        reasons.append("Uses raw IP address instead of domain name")

    if not f.has_https:
        score += 15
        reasons.append("No HTTPS — connection is unencrypted")

    if f.has_at_symbol:
        score += 20
        reasons.append("Contains '@' symbol — browser ignores everything before it")

    if f.has_double_slash:
        score += 10
        reasons.append("Double slash in path — possible redirect trick")

    if f.length > 75:
        score += 10
        reasons.append(f"Unusually long URL ({f.length} chars)")

    if f.num_dots > 4:
        score += 10
        reasons.append(f"Excessive dots ({f.num_dots}) — deep subdomain nesting")

    if f.num_hyphens > 3:
        score += 8
        reasons.append(f"Many hyphens ({f.num_hyphens}) in domain")

    if f.subdomain_depth > 2:
        score += 12
        reasons.append(f"Deep subdomain nesting (depth {f.subdomain_depth})")

    if f.brand_in_subdomain:
        score += 25
        reasons.append(f"Brand name(s) in subdomain: {', '.join(f.brand_in_subdomain)} — classic spoofing tactic")

    if f.suspicious_keywords:
        score += min(len(f.suspicious_keywords) * 5, 20)
        reasons.append(f"Phishing keywords found: {', '.join(f.suspicious_keywords[:4])}")

    if f.tld in SUSPICIOUS_TLDS:
        score += 20
        reasons.append(f"Suspicious TLD: {f.tld}")

    if f.entropy > 4.0:
        score += 10
        reasons.append(f"High domain entropy ({f.entropy:.2f}) — may be randomly generated")

    if f.num_digits > 5:
        score += 8
        reasons.append(f"Many digits in domain ({f.num_digits})")

    return min(score, 100), reasons


def classify(score: int) -> Tuple[str, str]:
    if score >= 60:
        return "LIKELY PHISHING", "🔴"
    elif score >= 35:
        return "SUSPICIOUS", "🟡"
    else:
        return "LIKELY SAFE", "🟢"


def analyze(url: str) -> None:
    print(f"\n{'='*55}")
    print(f"  URL: {url[:70]}{'...' if len(url) > 70 else ''}")
    print(f"{'='*55}")

    features = extract_features(url)
    score, reasons = score_url(features)
    verdict, icon = classify(score)

    print(f"\n  {icon}  Verdict : {verdict}")
    print(f"      Risk Score : {score}/100")

    print(f"\n  Features Extracted:")
    print(f"    HTTPS         : {'Yes' if features.has_https else 'No'}")
    print(f"    IP Address    : {'Yes' if features.has_ip else 'No'}")
    print(f"    TLD           : {features.tld or 'unknown'}")
    print(f"    Subdomain Depth: {features.subdomain_depth}")
    print(f"    URL Length    : {features.length}")
    print(f"    Domain Entropy: {features.entropy:.2f}")
    print(f"    @ Symbol      : {'Yes' if features.has_at_symbol else 'No'}")

    if reasons:
        print(f"\n  ⚠  Red Flags:")
        for r in reasons:
            print(f"    • {r}")
    else:
        print(f"\n  ✓  No significant red flags detected.")

    print()


def batch_analyze(urls: List[str]) -> None:
    print(f"\n{'='*55}")
    print(f"  BATCH ANALYSIS — {len(urls)} URLs")
    print(f"{'='*55}")
    print(f"  {'Score':>6}  {'Verdict':<18}  URL")
    print(f"  {'-'*6}  {'-'*18}  {'-'*30}")
    for url in urls:
        features = extract_features(url)
        score, _ = score_url(features)
        verdict, icon = classify(score)
        display = url[:45] + "..." if len(url) > 45 else url
        print(f"  {score:>5}%  {icon} {verdict:<16}  {display}")
    print()


# ── Demo ──────────────────────────────────────────────────────────────────────

DEMO_URLS = [
    "https://www.google.com/search?q=python",
    "http://192.168.1.1/login/secure/account/verify",
    "https://paypal.com-secure-login.xyz/signin?redirect=account",
    "http://amazon-account-verify.tk/update/password?token=abc123",
    "https://github.com/RedLight3303",
    "http://login.microsoftonline.com.phish-site.ml/auth",
    "https://ohio.edu/students",
]

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "--batch":
            batch_analyze(sys.argv[2:])
        else:
            for url in sys.argv[1:]:
                analyze(url)
    else:
        print("\n  Phishing URL Detector — Demo Mode")
        print("  Usage: python phishing_detector.py <url>  [<url2> ...]")
        print("         python phishing_detector.py --batch <url1> <url2> ...\n")
        batch_analyze(DEMO_URLS)
        analyze(DEMO_URLS[2])
