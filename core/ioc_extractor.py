"""
core/ioc_extractor.py
──────────────────────
Indicator of Compromise (IOC) Extraction from document content.

def extract_iocs(filepath: str) -> dict:
    """
    Scan the raw binary of a document for embedded IOCs.

    Returns:
        urls_found     : list of unique URLs found
        ips_found      : list of unique IPs found
        emails_found   : list of unique emails found
        ioc_summary    : counts of each IOC type
        forensic_flags : list of raised flags
    """
    result = {
        "urls_found":      [],
        "ips_found":       [],
        "emails_found":    [],
        "ioc_summary":     {},
        "forensic_flags":  []
    }

    try:
        with open(filepath, "rb") as f:
            raw = f.read()

        # Decode to string for regex (replace non-decodable bytes)
        text = raw.decode("utf-8", errors="replace")

        # Extract all IOCs
        urls   = list({u.rstrip(".,);'\"") for u in RE_URL.findall(text)})
        ips    = list(set(RE_IPV4.findall(text)))
        emails = list(set(RE_EMAIL.findall(text)))

        # Filter out private/loopback IPs (not suspicious)
        ips = [ip for ip in ips if not _is_private_ip(ip)]

        result["urls_found"]   = urls
        result["ips_found"]    = ips
        result["emails_found"] = emails
        result["ioc_summary"]  = {
            "total_urls":   len(urls),
            "total_ips":    len(ips),
            "total_emails": len(emails),
        }

        _apply_ioc_flags(result, urls, ips, emails)

    except Exception as e:
        result["error"] = str(e)

    return result


# ---
# HELPER FUNCTIONS
# ---

def _is_private_ip(ip: str) -> bool:
    """Return True if IP is a private/loopback/reserved address."""
    parts = list(map(int, ip.split(".")))
    return (
        parts[0] == 10 or
        parts[0] == 127 or
        (parts[0] == 172 and 16 <= parts[1] <= 31) or
        (parts[0] == 192 and parts[1] == 168) or
        (parts[0] == 169 and parts[1] == 254)
    )


def _extract_domain(url: str) -> str:
    """Extract the domain from a URL string."""
    url = url.lower().replace("https://", "").replace("http://", "")
    return url.split("/")[0].split("?")[0].split("#")[0]


def _apply_ioc_flags(result: dict, urls: List[str], ips: List[str], emails: List[str]):
    flags = result["forensic_flags"]

    # --- Rule 1: External URLs found ---
    external_urls = [u for u in urls if _extract_domain(u) not in SAFE_DOMAINS]
    if external_urls:
        flags.append({
            "severity": "HIGH",
            "code":     "SUSPICIOUS_URLS_FOUND",
            "detail":   (
                f"{len(external_urls)} external URL(s) embedded in document. "
                f"A genuine bank document should not contain external links. "
                f"URLs: {external_urls[:3]}{'...' if len(external_urls) > 3 else ''}"
            )
        })

    # --- Rule 2: Suspicious TLD in URL ---
    sus_tld_urls = []
    for url in urls:
        domain = _extract_domain(url)
        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            sus_tld_urls.append(url)
    if sus_tld_urls:
        flags.append({
            "severity": "HIGH",
            "code":     "SUSPICIOUS_DOMAIN",
            "detail":   (
                f"URL(s) with high-risk TLDs found: {sus_tld_urls[:2]}. "
                f"These TLDs are frequently used for phishing and malware distribution."
            )
        })

    # --- Rule 3: URL shortener detected (hiding real destination) ---
    short_urls = [u for u in urls if _extract_domain(u) in URL_SHORTENERS]
    if short_urls:
        flags.append({
            "severity": "HIGH",
            "code":     "URL_SHORTENER_DETECTED",
            "detail":   (
                f"URL shortener(s) found: {short_urls[:2]}. "
                f"Shorteners are used to disguise the real destination URL."
            )
        })

    # --- Rule 4: Public IP addresses embedded ---
    if ips:
        flags.append({
            "severity": "MEDIUM",
            "code":     "IP_ADDRESS_EMBEDDED",
            "detail":   (
                f"{len(ips)} public IP address(es) found: {ips[:3]}. "
                f"Raw IP addresses in documents often indicate callback/C2 infrastructure."
            )
        })

    # --- Rule 5: Suspicious email domains ---
    sus_emails = [e for e in emails
                  if not any(e.endswith(d) for d in ["@" + s for s in SAFE_DOMAINS])
                  and not e.endswith(".gov.in") and not e.endswith(".ac.in")]
    if len(sus_emails) > 3:
        # A salary slip with many email addresses is unusual
        flags.append({
            "severity": "LOW",
            "code":     "MANY_EMAIL_ADDRESSES",
            "detail":   (
                f"{len(sus_emails)} email address(es) found in document — "
                f"unusual for a standard bank document."
            )
        })
