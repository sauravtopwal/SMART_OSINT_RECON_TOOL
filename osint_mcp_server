"""
╔══════════════════════════════════════════════════════════════════════╗
║          SMART OSINT RECON AGENT — MCP SERVER (6 LAYERS)            ║
║          Drop into Claude Desktop via claude_desktop_config.json     ║
╠══════════════════════════════════════════════════════════════════════╣
║  INSTALL DEPS:                                                        ║
║    pip install mcp python-whois dnspython requests shodan            ║
║                                                                       ║
║  CONFIG (claude_desktop_config.json):                                 ║
║    {                                                                  ║
║      "mcpServers": {                                                  ║
║        "osint-agent": {                                               ║
║          "command": "/path/to/.venv/bin/python",                     ║
║          "args": ["/path/to/osint_mcp_server.py"]                    ║
║        }                                                              ║
║      }                                                                ║
║    }                                                                  ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import json
import socket
import re
import hashlib
from datetime import datetime
from typing import Any

# ── MCP Core ──────────────────────────────────────────────────────────
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# ── Optional deps (graceful fail if not installed) ────────────────────
try:
    import whois as python_whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import shodan as shodan_lib
    HAS_SHODAN = True
except ImportError:
    HAS_SHODAN = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ══════════════════════════════════════════════════════════════════════
#  CONFIG — set your API keys here
# ══════════════════════════════════════════════════════════════════════
CONFIG = {
    "SHODAN_API_KEY":   "YOUR_SHODAN_API_KEY",       # https://shodan.io
    "HIBP_API_KEY":     "YOUR_HIBP_API_KEY",          # https://haveibeenpwned.com/API/Key
    "VIRUSTOTAL_KEY":   "YOUR_VIRUSTOTAL_API_KEY",    # https://virustotal.com
    "ABUSEIPDB_KEY":    "YOUR_ABUSEIPDB_API_KEY",     # https://abuseipdb.com
}

# ══════════════════════════════════════════════════════════════════════
#  SERVER INIT
# ══════════════════════════════════════════════════════════════════════
server = Server("osint-recon-agent")

# ══════════════════════════════════════════════════════════════════════
#  LAYER 1 — INPUT HELPERS
# ══════════════════════════════════════════════════════════════════════

def classify_target(target: str) -> str:
    """Auto-detect what kind of target was given."""
    ip_pattern   = r"^\d{1,3}(\.\d{1,3}){3}$"
    domain_pat   = r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    email_pat    = r"^[^@]+@[^@]+\.[^@]+$"
    phone_pat    = r"^\+?[\d\s\-\(\)]{7,15}$"

    if re.match(ip_pattern, target):   return "ip"
    if re.match(email_pat, target):    return "email"
    if re.match(domain_pat, target):   return "domain"
    if re.match(phone_pat, target):    return "phone"
    return "person_or_username"

# ══════════════════════════════════════════════════════════════════════
#  LAYER 3a — PASSIVE RECON MODULE
# ══════════════════════════════════════════════════════════════════════

async def run_whois(domain: str) -> dict:
    """WHOIS lookup — registrar, dates, nameservers, registrant."""
    if not HAS_WHOIS:
        return {"error": "python-whois not installed. Run: pip install python-whois"}
    try:
        w = python_whois.whois(domain)
        return {
            "domain":      str(w.domain_name),
            "registrar":   str(w.registrar),
            "created":     str(w.creation_date),
            "expires":     str(w.expiration_date),
            "updated":     str(w.updated_date),
            "nameservers": list(w.name_servers or []),
            "emails":      list(w.emails or []),
            "org":         str(w.org),
            "country":     str(w.country),
            "status":      str(w.status),
        }
    except Exception as e:
        return {"error": str(e)}


async def run_dns_lookup(domain: str) -> dict:
    """DNS enumeration — A, AAAA, MX, TXT, NS, CNAME, SOA records."""
    if not HAS_DNS:
        return {"error": "dnspython not installed. Run: pip install dnspython"}
    results = {}
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            results[rtype] = [str(r) for r in answers]
        except Exception:
            pass
    return results


async def run_subdomain_enum(domain: str) -> dict:
    """Subdomain discovery via crt.sh certificate transparency logs."""
    if not HAS_REQUESTS:
        return {"error": "requests not installed. Run: pip install requests"}
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15,
            headers={"User-Agent": "OSINT-Recon-Agent/1.0"}
        )
        entries = r.json()
        subdomains = sorted(set(
            entry["name_value"]
            for entry in entries
            if "*" not in entry["name_value"]
        ))
        return {
            "domain":    domain,
            "count":     len(subdomains),
            "subdomains": subdomains[:100],  # cap at 100
        }
    except Exception as e:
        return {"error": str(e)}


async def run_rdap_lookup(domain: str) -> dict:
    """RDAP (modern WHOIS replacement) lookup."""
    if not HAS_REQUESTS:
        return {"error": "requests not installed"}
    try:
        r = requests.get(
            f"https://rdap.org/domain/{domain}",
            timeout=10,
            headers={"Accept": "application/json"}
        )
        data = r.json()
        result = {
            "handle":      data.get("handle"),
            "ldhName":     data.get("ldhName"),
            "status":      data.get("status", []),
            "events":      [
                {"action": e.get("eventAction"), "date": e.get("eventDate")}
                for e in data.get("events", [])
            ],
        }
        # Extract registrar from entities
        for entity in data.get("entities", []):
            for role in entity.get("roles", []):
                if role == "registrar":
                    vcard = entity.get("vcardArray", [])
                    result["registrar"] = str(vcard)
        return result
    except Exception as e:
        return {"error": str(e)}


# ══════════════════════════════════════════════════════════════════════
#  LAYER 3b — OSINT SOURCES MODULE
# ══════════════════════════════════════════════════════════════════════

async def run_breach_check(email: str) -> dict:
    """Check email against HaveIBeenPwned breach database."""
    if not HAS_REQUESTS:
        return {"error": "requests not installed"}
    if CONFIG["HIBP_API_KEY"] == "YOUR_HIBP_API_KEY":
        return {"warning": "HIBP API key not set in CONFIG", "email": email}
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers={
                "hibp-api-key": CONFIG["HIBP_API_KEY"],
                "User-Agent":   "OSINT-Recon-Agent/1.0",
            },
            timeout=10
        )
        if r.status_code == 404:
            return {"email": email, "breaches": [], "count": 0, "status": "clean"}
        if r.status_code == 200:
            breaches = r.json()
            return {
                "email":   email,
                "count":   len(breaches),
                "status":  "compromised",
                "breaches": [
                    {
                        "name":         b.get("Name"),
                        "domain":       b.get("Domain"),
                        "breach_date":  b.get("BreachDate"),
                        "data_classes": b.get("DataClasses", []),
                        "pwn_count":    b.get("PwnCount"),
                    }
                    for b in breaches
                ],
            }
        return {"error": f"HTTP {r.status_code}: {r.text}"}
    except Exception as e:
        return {"error": str(e)}


async def run_github_dork(query: str) -> dict:
    """Search GitHub for exposed secrets, configs, credentials."""
    if not HAS_REQUESTS:
        return {"error": "requests not installed"}
    dork_queries = [
        f"{query} password",
        f"{query} api_key",
        f"{query} secret",
        f"{query} config",
    ]
    results = []
    try:
        for dork in dork_queries[:2]:  # limit to avoid rate limit
            r = requests.get(
                "https://api.github.com/search/code",
                params={"q": dork, "per_page": 5},
                headers={
                    "Accept":     "application/vnd.github.v3+json",
                    "User-Agent": "OSINT-Recon-Agent/1.0"
                },
                timeout=10
            )
            if r.status_code == 200:
                items = r.json().get("items", [])
                for item in items:
                    results.append({
                        "repo":     item.get("repository", {}).get("full_name"),
                        "file":     item.get("name"),
                        "path":     item.get("path"),
                        "url":      item.get("html_url"),
                    })
        return {"query": query, "count": len(results), "results": results}
    except Exception as e:
        return {"error": str(e)}


async def run_email_permutations(name: str, domain: str) -> dict:
    """Generate likely email formats from a person's name + domain."""
    parts = name.lower().split()
    if len(parts) < 2:
        first, last = parts[0], parts[0]
    else:
        first, last = parts[0], parts[-1]

    permutations = [
        f"{first}@{domain}",
        f"{last}@{domain}",
        f"{first}.{last}@{domain}",
        f"{first[0]}{last}@{domain}",
        f"{first}{last[0]}@{domain}",
        f"{first}_{last}@{domain}",
        f"{last}.{first}@{domain}",
        f"{first}{last}@{domain}",
    ]
    return {
        "name":          name,
        "domain":        domain,
        "permutations":  permutations,
        "tip":           "Use breach_check tool on each to find valid ones",
    }


async def run_pastebin_search(query: str) -> dict:
    """Search Pastebin for exposed data mentioning the target."""
    if not HAS_REQUESTS:
        return {"error": "requests not installed"}
    try:
        # Google-dork Pastebin via a public search API
        r = requests.get(
            "https://psbdmp.ws/api/v3/search/" + query,
            timeout=10,
            headers={"User-Agent": "OSINT-Recon-Agent/1.0"}
        )
        if r.status_code == 200:
            data = r.json()
            return {
                "query":   query,
                "count":   data.get("count", 0),
                "results": data.get("data", [])[:10],
            }
        return {"query": query, "status": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


# ══════════════════════════════════════════════════════════════════════
#  LAYER 3c — TECHNICAL RECON MODULE
# ══════════════════════════════════════════════════════════════════════

async def run_shodan_lookup(target: str) -> dict:
    """Shodan host lookup — open ports, services, CVEs, banners."""
    if not HAS_SHODAN:
        return {"error": "shodan not installed. Run: pip install shodan"}
    if CONFIG["SHODAN_API_KEY"] == "YOUR_SHODAN_API_KEY":
        return {"warning": "Shodan API key not set in CONFIG", "target": target}
    try:
        api = shodan_lib.Shodan(CONFIG["SHODAN_API_KEY"])
        # Resolve domain to IP if needed
        ip = target
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
            ip = socket.gethostbyname(target)

        host = api.host(ip)
        return {
            "ip":           host.get("ip_str"),
            "org":          host.get("org"),
            "isp":          host.get("isp"),
            "asn":          host.get("asn"),
            "country":      host.get("country_name"),
            "city":         host.get("city"),
            "os":           host.get("os"),
            "last_update":  host.get("last_update"),
            "ports":        host.get("ports", []),
            "vulns":        list(host.get("vulns", {}).keys()),
            "services":     [
                {
                    "port":      item.get("port"),
                    "transport": item.get("transport"),
                    "product":   item.get("product"),
                    "version":   item.get("version"),
                    "banner":    item.get("data", "")[:200],
                }
                for item in host.get("data", [])[:10]
            ],
        }
    except shodan_lib.exception.APIError as e:
        return {"error": f"Shodan API Error: {str(e)}"}
    except Exception as e:
        return {"error": str(e)}


async def run_http_headers(url: str) -> dict:
    """Fetch and analyze HTTP headers — server, CSP, tech fingerprint."""
    if not HAS_REQUESTS:
        return {"error": "requests not installed"}
    if not url.startswith("http"):
        url = "https://" + url
    try:
        r = requests.head(
            url, timeout=10, allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (OSINT-Recon-Agent/1.0)"}
        )
        headers = dict(r.headers)
        # Security header analysis
        security = {
            "hsts":            "Strict-Transport-Security" in headers,
            "x_frame":         "X-Frame-Options" in headers,
            "csp":             "Content-Security-Policy" in headers,
            "x_content_type":  "X-Content-Type-Options" in headers,
            "referrer_policy": "Referrer-Policy" in headers,
        }
        # Tech fingerprint
        tech = []
        server = headers.get("Server", "")
        powered = headers.get("X-Powered-By", "")
        if server:   tech.append(f"Server: {server}")
        if powered:  tech.append(f"Powered-By: {powered}")

        return {
            "url":            r.url,
            "status_code":    r.status_code,
            "headers":        headers,
            "security_score": f"{sum(security.values())}/5",
            "security":       security,
            "tech_hints":     tech,
            "cookies":        [str(c) for c in r.cookies],
        }
    except Exception as e:
        return {"error": str(e)}


async def run_ssl_cert_analysis(domain: str) -> dict:
    """SSL/TLS certificate analysis — validity, SANs, issuer."""
    if not HAS_REQUESTS:
        return {"error": "requests not installed"}
    try:
        import ssl
        import OpenSSL.crypto as crypto  # pip install pyopenssl
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.create_connection((domain, 443), timeout=10),
            server_hostname=domain
        )
        cert_bin = conn.getpeercert(binary_form=True)
        conn.close()
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
        subject   = dict(x509.get_subject().get_components())
        issuer    = dict(x509.get_issuer().get_components())
        not_after = datetime.strptime(x509.get_notAfter().decode(), "%Y%m%d%H%M%SZ")
        days_left = (not_after - datetime.utcnow()).days
        # Extract SANs
        sans = []
        for i in range(x509.get_extension_count()):
            ext = x509.get_extension(i)
            if b"subjectAltName" in ext.get_short_name():
                sans = [s.strip() for s in str(ext).split(",")]

        return {
            "domain":           domain,
            "subject":          {k.decode(): v.decode() for k, v in subject.items()},
            "issuer":           {k.decode(): v.decode() for k, v in issuer.items()},
            "not_before":       str(x509.get_notBefore()),
            "not_after":        str(not_after),
            "days_remaining":   days_left,
            "expired":          days_left < 0,
            "serial_number":    str(x509.get_serial_number()),
            "san_count":        len(sans),
            "sans":             sans[:20],
        }
    except ImportError:
        # Fallback without pyopenssl — use crt.sh
        try:
            r = requests.get(
                f"https://crt.sh/?q={domain}&output=json",
                timeout=10
            )
            certs = r.json()[:5]
            return {
                "domain":  domain,
                "note":    "Install pyopenssl for full cert details",
                "recent_certs": [
                    {
                        "issuer":       c.get("issuer_name"),
                        "not_before":   c.get("not_before"),
                        "not_after":    c.get("not_after"),
                        "common_name":  c.get("common_name"),
                    }
                    for c in certs
                ],
            }
        except Exception as e:
            return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}


async def run_ip_reputation(ip: str) -> dict:
    """Check IP reputation across AbuseIPDB and VirusTotal."""
    if not HAS_REQUESTS:
        return {"error": "requests not installed"}
    results = {"ip": ip}

    # AbuseIPDB
    if CONFIG["ABUSEIPDB_KEY"] != "YOUR_ABUSEIPDB_API_KEY":
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                headers={
                    "Key":    CONFIG["ABUSEIPDB_KEY"],
                    "Accept": "application/json"
                },
                timeout=10
            )
            data = r.json().get("data", {})
            results["abuseipdb"] = {
                "abuse_confidence": data.get("abuseConfidenceScore"),
                "total_reports":    data.get("totalReports"),
                "country":          data.get("countryCode"),
                "isp":              data.get("isp"),
                "domain":           data.get("domain"),
                "is_tor":           data.get("isTor"),
                "is_whitelisted":   data.get("isWhitelisted"),
            }
        except Exception as e:
            results["abuseipdb"] = {"error": str(e)}
    else:
        results["abuseipdb"] = {"warning": "AbuseIPDB API key not configured"}

    # VirusTotal
    if CONFIG["VIRUSTOTAL_KEY"] != "YOUR_VIRUSTOTAL_API_KEY":
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": CONFIG["VIRUSTOTAL_KEY"]},
                timeout=10
            )
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            results["virustotal"] = {
                "malicious":   stats.get("malicious", 0),
                "suspicious":  stats.get("suspicious", 0),
                "harmless":    stats.get("harmless", 0),
                "reputation":  data.get("reputation"),
                "country":     data.get("country"),
                "as_owner":    data.get("as_owner"),
            }
        except Exception as e:
            results["virustotal"] = {"error": str(e)}
    else:
        results["virustotal"] = {"warning": "VirusTotal API key not configured"}

    return results


# ══════════════════════════════════════════════════════════════════════
#  LAYER 3d — DEEP / DARK WEB MODULE
# ══════════════════════════════════════════════════════════════════════

async def run_threat_intel(target: str) -> dict:
    """Aggregate threat intelligence from public feeds."""
    if not HAS_REQUESTS:
        return {"error": "requests not installed"}
    results = {"target": target, "feeds": {}}

    # URLhaus — malware URL feed
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": target},
            timeout=10
        )
        data = r.json()
        results["feeds"]["urlhaus"] = {
            "query_status": data.get("query_status"),
            "urls_count":   len(data.get("urls", [])),
            "urls":         data.get("urls", [])[:5],
        }
    except Exception as e:
        results["feeds"]["urlhaus"] = {"error": str(e)}

    # ThreatFox — IOC intelligence
    try:
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": target},
            timeout=10
        )
        data = r.json()
        results["feeds"]["threatfox"] = {
            "query_status": data.get("query_status"),
            "iocs":         data.get("data", [])[:5],
        }
    except Exception as e:
        results["feeds"]["threatfox"] = {"error": str(e)}

    return results


# ══════════════════════════════════════════════════════════════════════
#  LAYER 4 — AGGREGATION MODULE
# ══════════════════════════════════════════════════════════════════════

async def run_full_passive_recon(domain: str) -> dict:
    """Run ALL passive recon in one call: WHOIS + DNS + subdomains + RDAP."""
    results = {
        "target":     domain,
        "type":       classify_target(domain),
        "timestamp":  datetime.utcnow().isoformat(),
        "whois":      await run_whois(domain),
        "dns":        await run_dns_lookup(domain),
        "subdomains": await run_subdomain_enum(domain),
        "rdap":       await run_rdap_lookup(domain),
    }
    # Extract emails found across sources
    emails = set()
    for email in results["whois"].get("emails", []):
        if email:
            emails.add(email)
    results["discovered_emails"] = list(emails)
    return results


# ══════════════════════════════════════════════════════════════════════
#  LAYER 5 — SCORING ENGINE
# ══════════════════════════════════════════════════════════════════════

async def run_risk_score(findings: str) -> dict:
    """
    Score aggregated OSINT findings.
    Pass in a JSON string of combined results.
    Returns severity ratings per category.
    """
    try:
        data = json.loads(findings)
    except Exception:
        data = {"raw": findings}

    score   = 0
    risks   = []
    details = {}

    # ── Check for breaches ──
    if "breach_check" in data or "breaches" in data:
        breach_data = data.get("breach_check", data.get("breaches", {}))
        count = breach_data.get("count", 0)
        if count > 0:
            sev = "CRITICAL" if count > 5 else "HIGH" if count > 1 else "MEDIUM"
            score += {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10}[sev]
            risks.append({"category": "Data Breach", "severity": sev,
                          "detail": f"Found in {count} breach(es)"})
            details["breach"] = {"severity": sev, "count": count}

    # ── Check for open ports / Shodan ──
    if "shodan" in data:
        ports = data["shodan"].get("ports", [])
        vulns = data["shodan"].get("vulns", [])
        if vulns:
            score += 35
            risks.append({"category": "Known CVEs", "severity": "CRITICAL",
                          "detail": f"CVEs found: {', '.join(vulns[:5])}"})
        elif len(ports) > 10:
            score += 15
            risks.append({"category": "Attack Surface", "severity": "HIGH",
                          "detail": f"{len(ports)} open ports detected"})
        details["shodan"] = {"ports": len(ports), "cves": len(vulns)}

    # ── Check SSL ──
    if "ssl" in data:
        ssl_data = data["ssl"]
        if ssl_data.get("expired"):
            score += 20
            risks.append({"category": "SSL Certificate", "severity": "HIGH",
                          "detail": "Certificate is EXPIRED"})
        elif ssl_data.get("days_remaining", 999) < 14:
            score += 10
            risks.append({"category": "SSL Certificate", "severity": "MEDIUM",
                          "detail": f"Expires in {ssl_data['days_remaining']} days"})

    # ── Check IP reputation ──
    if "reputation" in data or "abuseipdb" in data:
        rep = data.get("reputation", data.get("abuseipdb", {}))
        abuse = rep.get("abuse_confidence", 0)
        if abuse > 75:
            score += 30
            risks.append({"category": "IP Reputation", "severity": "CRITICAL",
                          "detail": f"Abuse confidence: {abuse}%"})
        elif abuse > 30:
            score += 15
            risks.append({"category": "IP Reputation", "severity": "HIGH",
                          "detail": f"Abuse confidence: {abuse}%"})

    # ── Check subdomains (large attack surface) ──
    if "subdomains" in data:
        count = data["subdomains"].get("count", 0)
        if count > 50:
            score += 10
            risks.append({"category": "Attack Surface", "severity": "MEDIUM",
                          "detail": f"Large subdomain footprint: {count} subdomains"})

    # ── Check GitHub leaks ──
    if "github" in data:
        leaks = data["github"].get("count", 0)
        if leaks > 0:
            score += 20
            risks.append({"category": "Leaked Secrets", "severity": "HIGH",
                          "detail": f"{leaks} potential leaks on GitHub"})

    # ── Overall rating ──
    if score >= 80:     overall = "CRITICAL"
    elif score >= 50:   overall = "HIGH"
    elif score >= 25:   overall = "MEDIUM"
    elif score > 0:     overall = "LOW"
    else:               overall = "INFORMATIONAL"

    return {
        "overall_severity":  overall,
        "risk_score":        min(score, 100),
        "risk_score_label":  f"{min(score, 100)}/100",
        "findings_count":    len(risks),
        "risks":             sorted(risks, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x["severity"])),
        "details":           details,
        "recommendation":    {
            "CRITICAL":      "Immediate action required. Notify security team.",
            "HIGH":          "Investigate within 24 hours.",
            "MEDIUM":        "Review and remediate within 7 days.",
            "LOW":           "Monitor and document findings.",
            "INFORMATIONAL": "No significant risks detected.",
        }.get(overall, "Review findings manually."),
        "generated_at": datetime.utcnow().isoformat(),
    }


# ══════════════════════════════════════════════════════════════════════
#  LAYER 6 — REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════════

async def generate_report(target: str, findings_json: str) -> dict:
    """Generate a structured Markdown recon report."""
    try:
        findings = json.loads(findings_json)
    except Exception:
        findings = {"data": findings_json}

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    target_type = classify_target(target)

    report = f"""# OSINT Recon Report
**Target:** `{target}`
**Type:** {target_type}
**Generated:** {timestamp}
**Report ID:** {hashlib.md5(f"{target}{timestamp}".encode()).hexdigest()[:8].upper()}

---

## Executive Summary
Target `{target}` was analyzed across passive recon, OSINT sources, technical fingerprinting, threat intelligence, and breach databases. Findings are summarized below.

---

## Findings
"""
    # Add each section
    for key, value in findings.items():
        if isinstance(value, dict) and "error" not in value:
            report += f"\n### {key.replace('_', ' ').title()}\n"
            report += f"```json\n{json.dumps(value, indent=2, default=str)[:1500]}\n```\n"

    report += f"""
---

## Risk Assessment
See `risk_score` tool output for full severity breakdown.

---

## Recommendations
1. Review all discovered subdomains for unnecessary exposure
2. Check all discovered emails against breach databases
3. Patch any CVEs identified by Shodan
4. Ensure SSL certificates are valid and auto-renewing
5. Rotate any credentials found in GitHub leaks

---
*Generated by Smart OSINT Recon Agent · MCP Server v1.0*
"""
    return {
        "target":        target,
        "report":        report,
        "char_count":    len(report),
        "note":          "Copy the 'report' field value for your full Markdown report",
    }


# ══════════════════════════════════════════════════════════════════════
#  MCP TOOL REGISTRY
# ══════════════════════════════════════════════════════════════════════

@server.list_tools()
async def list_tools():
    return [
        # ── Layer 1 ──
        Tool(
            name="classify_target",
            description="Auto-detect whether a target is a domain, IP, email, phone, or person name",
            inputSchema={"type":"object","properties":{"target":{"type":"string","description":"Any target: domain, IP, email, username, phone"}},"required":["target"]}
        ),
        # ── Layer 3a: Passive Recon ──
        Tool(
            name="whois_lookup",
            description="WHOIS lookup — registrar, creation date, expiry, nameservers, registrant email",
            inputSchema={"type":"object","properties":{"domain":{"type":"string"}},"required":["domain"]}
        ),
        Tool(
            name="dns_lookup",
            description="Full DNS enumeration — A, AAAA, MX, TXT, NS, CNAME, SOA records",
            inputSchema={"type":"object","properties":{"domain":{"type":"string"}},"required":["domain"]}
        ),
        Tool(
            name="subdomain_enum",
            description="Discover subdomains via crt.sh certificate transparency logs",
            inputSchema={"type":"object","properties":{"domain":{"type":"string"}},"required":["domain"]}
        ),
        Tool(
            name="rdap_lookup",
            description="RDAP modern WHOIS lookup — structured domain registration data",
            inputSchema={"type":"object","properties":{"domain":{"type":"string"}},"required":["domain"]}
        ),
        # ── Layer 3b: OSINT Sources ──
        Tool(
            name="breach_check",
            description="Check if an email appears in known data breaches via HaveIBeenPwned",
            inputSchema={"type":"object","properties":{"email":{"type":"string"}},"required":["email"]}
        ),
        Tool(
            name="email_permutations",
            description="Generate likely email formats from a person's name and their company domain",
            inputSchema={"type":"object","properties":{"name":{"type":"string"},"domain":{"type":"string"}},"required":["name","domain"]}
        ),
        Tool(
            name="github_dork",
            description="Search GitHub for exposed secrets, API keys, passwords related to a target",
            inputSchema={"type":"object","properties":{"query":{"type":"string","description":"Company name, domain, or keyword to search for"}},"required":["query"]}
        ),
        Tool(
            name="pastebin_search",
            description="Search Pastebin dumps for exposed data mentioning the target",
            inputSchema={"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}
        ),
        # ── Layer 3c: Technical Recon ──
        Tool(
            name="shodan_lookup",
            description="Shodan lookup — open ports, running services, banners, known CVEs for a domain or IP",
            inputSchema={"type":"object","properties":{"target":{"type":"string","description":"Domain or IP address"}},"required":["target"]}
        ),
        Tool(
            name="http_headers",
            description="Fetch HTTP headers — server fingerprint, security headers score, tech stack hints",
            inputSchema={"type":"object","properties":{"url":{"type":"string","description":"URL or domain (https:// added automatically)"}},"required":["url"]}
        ),
        Tool(
            name="ssl_cert_analysis",
            description="Analyze SSL/TLS certificate — validity, days remaining, SANs, issuer chain",
            inputSchema={"type":"object","properties":{"domain":{"type":"string"}},"required":["domain"]}
        ),
        Tool(
            name="ip_reputation",
            description="Check IP reputation via AbuseIPDB and VirusTotal",
            inputSchema={"type":"object","properties":{"ip":{"type":"string"}},"required":["ip"]}
        ),
        # ── Layer 3d: Threat Intel ──
        Tool(
            name="threat_intel",
            description="Check target against URLhaus malware feed and ThreatFox IOC database",
            inputSchema={"type":"object","properties":{"target":{"type":"string","description":"Domain, IP, or URL to check"}},"required":["target"]}
        ),
        # ── Layer 4: Aggregation ──
        Tool(
            name="full_passive_recon",
            description="Run complete passive recon in one call: WHOIS + DNS + subdomains + RDAP + email discovery",
            inputSchema={"type":"object","properties":{"domain":{"type":"string"}},"required":["domain"]}
        ),
        # ── Layer 5: Scoring ──
        Tool(
            name="risk_score",
            description="Score all aggregated OSINT findings — returns severity rating (CRITICAL/HIGH/MEDIUM/LOW), risk score out of 100, and prioritized recommendations",
            inputSchema={"type":"object","properties":{"findings":{"type":"string","description":"JSON string of combined tool results"}},"required":["findings"]}
        ),
        # ── Layer 6: Output ──
        Tool(
            name="generate_report",
            description="Generate a structured Markdown recon report from all collected findings",
            inputSchema={"type":"object","properties":{"target":{"type":"string"},"findings_json":{"type":"string","description":"JSON string of all findings"}},"required":["target","findings_json"]}
        ),
    ]


# ══════════════════════════════════════════════════════════════════════
#  MCP TOOL DISPATCH
# ══════════════════════════════════════════════════════════════════════

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        # ── Layer 1 ──
        if name == "classify_target":
            result = {"target": arguments["target"], "type": classify_target(arguments["target"])}

        # ── Layer 3a ──
        elif name == "whois_lookup":
            result = await run_whois(arguments["domain"])
        elif name == "dns_lookup":
            result = await run_dns_lookup(arguments["domain"])
        elif name == "subdomain_enum":
            result = await run_subdomain_enum(arguments["domain"])
        elif name == "rdap_lookup":
            result = await run_rdap_lookup(arguments["domain"])

        # ── Layer 3b ──
        elif name == "breach_check":
            result = await run_breach_check(arguments["email"])
        elif name == "email_permutations":
            result = await run_email_permutations(arguments["name"], arguments["domain"])
        elif name == "github_dork":
            result = await run_github_dork(arguments["query"])
        elif name == "pastebin_search":
            result = await run_pastebin_search(arguments["query"])

        # ── Layer 3c ──
        elif name == "shodan_lookup":
            result = await run_shodan_lookup(arguments["target"])
        elif name == "http_headers":
            result = await run_http_headers(arguments["url"])
        elif name == "ssl_cert_analysis":
            result = await run_ssl_cert_analysis(arguments["domain"])
        elif name == "ip_reputation":
            result = await run_ip_reputation(arguments["ip"])

        # ── Layer 3d ──
        elif name == "threat_intel":
            result = await run_threat_intel(arguments["target"])

        # ── Layer 4 ──
        elif name == "full_passive_recon":
            result = await run_full_passive_recon(arguments["domain"])

        # ── Layer 5 ──
        elif name == "risk_score":
            result = await run_risk_score(arguments["findings"])

        # ── Layer 6 ──
        elif name == "generate_report":
            result = await generate_report(arguments["target"], arguments["findings_json"])

        else:
            result = {"error": f"Unknown tool: {name}"}

    except Exception as e:
        result = {"error": f"Tool '{name}' failed: {str(e)}"}

    return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]


# ══════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )

if __name__ == "__main__":
    asyncio.run(main())
