#!/usr/bin/env python3
"""
SpoofScore — Multi-Layer Email Security Scanner

Scans any domain across 8 security layers and produces a composite score (0-100).
Answers one question: "Can someone impersonate this domain via email?"

Usage:
    python spoofscore.py example.com                     # scan one domain
    python spoofscore.py example.com another.org         # scan multiple domains
    python spoofscore.py -f domains.txt                  # scan from file (one domain per line)
    python spoofscore.py -f domains.txt -o results.csv   # output to CSV
    python spoofscore.py example.com --json              # JSON output
    python spoofscore.py example.com --smtp-threads 20   # custom thread count

Layers:
    1. DNS Authentication — MX, SPF record & policy, DMARC record & policy, DKIM selectors
    2. SMTP/TLS Probing   — STARTTLS support, TLS version, cipher suite, SMTP banner
    3. Mail Platform       — Fingerprint MX hostname (Google, Microsoft 365, self-hosted, etc.)
    4. SPF Chain Analysis  — Recursive include walking, RFC 7208 10-lookup limit, dangling includes
    5. Transport Security  — MTA-STS (RFC 8461), DANE/TLSA (RFC 7672), BIMI, TLS-RPT
    6. Composite Score     — Weighted 0-100 score with letter grade (A/B/C/D/F)

Unlike generic email configuration auditors, SpoofScore focuses on spoofability:
"Can someone impersonate this domain?" — not just "is the domain configured correctly?"

Requires: dnspython (pip install dnspython)
Port 25 access required for Layer 2 (SMTP probing). If blocked, Layer 2 returns "Blocked"
and the score is calculated without TLS points.

License: MIT
"""

import argparse
import csv
import json
import smtplib
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import dns.resolver
    import dns.rdatatype
except ImportError:
    print("ERROR: dnspython is required.\n  pip install dnspython")
    sys.exit(1)

__version__ = "2.0.0"

DKIM_SELECTORS = [
    "default", "google", "google2048", "gm1", "gm2", "gm3",
    "selector1", "selector2", "selector3",
    "k1", "k2", "k3", "mail", "dkim", "dkim1", "dkim2",
    "s1", "s2", "s3",
    "protonmail", "protonmail2", "protonmail3",
    "amazonses", "ses",
    "zoho", "zmail",
    "mandrill", "smtp", "cm", "mxvault", "mg",
    "postmark", "pm",
    "sendgrid", "smtpapi", "em",
    "sparkpost", "mailchimp", "turbo-smtp", "mailgun", "mailo",
    "ev1", "mta",
    "fm1", "fm2", "fm3",
    "resend", "mailjet",
    "mimecast", "mimecast20190104",
    "zendesk1", "zendesk2",
    "hs1", "hs2", "hubspot",
    "dk", "dksel", "email",
    "krs", "ml", "a1", "a2",
    "e1", "e2", "mx",
    "key1", "key2",
    "sig1", "smtp2go",
    "mandrill._domainkey", "turbo",
    "20230601", "20221208", "20210112",
    "s1024", "s2048",
    "selector", "primary",
]

RBL_ZONES = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
    "cbl.abuseat.org",
    "dnsbl-1.uceprotect.net",
    "psbl.surriel.com",
    "all.s5h.net",
    "rbl.megarbl.net",
    "combined.abuse.ch",
]

PLATFORM_PATTERNS = [
    ("Google Workspace",  ["google.com", "googlemail.com", "smtp.google.com"]),
    ("Microsoft 365",     [".outlook.com", "protection.outlook.com", "mail.protection"]),
    ("Amazon SES",        ["amazonaws.com", "amazonses.com"]),
    ("Zoho",              ["zoho.com", "zohomail.com"]),
    ("ProtonMail",        ["protonmail.ch", "proton.ch"]),
    ("Yandex",            ["yandex.net", "yandex.ru"]),
    ("Barracuda",         ["barracudanetworks.com", "barracuda.com"]),
    ("Mimecast",          ["mimecast.com"]),
    ("Symantec/Broadcom", ["messagelabs.com", "symanteccloud.com"]),
    ("Cisco IronPort",    ["iphmx.com"]),
    ("Trend Micro",       ["tmes.trendmicro.com"]),
]

SMTP_TIMEOUT = 15


def make_resolver():
    r = dns.resolver.Resolver()
    r.lifetime = 10
    r.timeout = 8
    return r


# ═══════════════════════════════════════════════════════════════
# Layer 1: DNS Authentication
# ═══════════════════════════════════════════════════════════════

def check_mx(domain):
    try:
        r = make_resolver()
        answers = r.resolve(domain, "MX")
        mx_list = sorted(answers, key=lambda x: x.preference)
        primary = str(mx_list[0].exchange).rstrip(".")
        all_mx = [str(a.exchange).rstrip(".") for a in mx_list]
        return {"has_mx": True, "mx_primary": primary, "mx_all": all_mx}
    except Exception:
        return {"has_mx": False, "mx_primary": None, "mx_all": []}


def check_spf(domain):
    result = {"spf_record": "", "spf_mechanism": "missing"}
    try:
        r = make_resolver()
        answers = r.resolve(domain, "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.lower().startswith("v=spf1"):
                result["spf_record"] = txt
                low = txt.lower()
                if "-all" in low:
                    result["spf_mechanism"] = "hardfail"
                elif "~all" in low:
                    result["spf_mechanism"] = "softfail"
                elif "?all" in low:
                    result["spf_mechanism"] = "neutral"
                elif "+all" in low:
                    result["spf_mechanism"] = "permissive"
                else:
                    result["spf_mechanism"] = "present"
                break
    except Exception:
        pass
    return result


def check_dmarc(domain):
    result = {
        "dmarc_record": "", "dmarc_policy": "missing",
        "dmarc_sp": "", "dmarc_pct": "", "dmarc_rua": "", "dmarc_ruf": "",
    }
    try:
        r = make_resolver()
        answers = r.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if "v=DMARC1" in txt or "v=dmarc1" in txt.lower():
                result["dmarc_record"] = txt
                tags = {}
                for part in txt.split(";"):
                    part = part.strip()
                    if "=" in part:
                        k, v = part.split("=", 1)
                        tags[k.strip().lower()] = v.strip()
                result["dmarc_policy"] = tags.get("p", "missing")
                result["dmarc_sp"] = tags.get("sp", "")
                result["dmarc_pct"] = tags.get("pct", "")
                result["dmarc_rua"] = tags.get("rua", "")
                result["dmarc_ruf"] = tags.get("ruf", "")
                break
    except Exception:
        pass
    return result


PROVIDER_DKIM_SELECTORS = {
    "Google Workspace": ["google", "google2048", "gm1", "gm2", "gm3"],
    "Microsoft 365": ["selector1", "selector2"],
    "Amazon SES": ["amazonses", "ses", "ug7nbtf4gccmlpwj322ax3p6ow6yfsug"],
    "Zoho": ["zoho", "zmail"],
    "ProtonMail": ["protonmail", "protonmail2", "protonmail3"],
    "Mimecast": ["mimecast20190104", "mimecast"],
}

def check_dkim(domain, platform=None):
    import uuid
    r = make_resolver()

    canary = f"emailscore-wc-{uuid.uuid4().hex[:8]}"
    try:
        r.resolve(f"{canary}._domainkey.{domain}", "TXT")
        return {"dkim_selectors": [], "dkim_found": False, "dkim_wildcard": True}
    except dns.resolver.NXDOMAIN:
        pass
    except Exception:
        pass

    found = []
    selectors = list(DKIM_SELECTORS)
    if platform and platform in PROVIDER_DKIM_SELECTORS:
        provider_sels = PROVIDER_DKIM_SELECTORS[platform]
        selectors = provider_sels + [s for s in selectors if s not in provider_sels]
    seen = set()
    for sel in selectors:
        if sel in seen:
            continue
        seen.add(sel)
        try:
            answers = r.resolve(f"{sel}._domainkey.{domain}", "TXT")
            for rdata in answers:
                txt = rdata.to_text()
                if "p=" in txt:
                    found.append(sel)
                    break
        except Exception:
            pass
    return {"dkim_selectors": found, "dkim_found": len(found) > 0, "dkim_wildcard": False}


# ═══════════════════════════════════════════════════════════════
# Layer 2: SMTP/TLS Probing
# ═══════════════════════════════════════════════════════════════

def probe_smtp(mx_host):
    result = {
        "starttls": "No MX", "tls_version": "", "tls_cipher": "", "smtp_banner": "",
    }
    if not mx_host:
        return result

    try:
        server = smtplib.SMTP(mx_host, 25, timeout=SMTP_TIMEOUT)
        server.ehlo("emailscore.local")
        result["smtp_banner"] = (server.ehlo_resp or b"").decode("utf-8", errors="replace")[:80]

        if server.has_extn("STARTTLS"):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            server.starttls(context=ctx)
            server.ehlo("emailscore.local")
            sock = server.sock
            if isinstance(sock, ssl.SSLSocket):
                result["starttls"] = "Yes"
                result["tls_version"] = sock.version() or ""
                ci = sock.cipher()
                result["tls_cipher"] = ci[0] if ci else ""
            else:
                result["starttls"] = "Yes"
        else:
            result["starttls"] = "No"

        try:
            server.quit()
        except Exception:
            pass

    except socket.timeout:
        result["starttls"] = "Timeout"
    except ConnectionRefusedError:
        result["starttls"] = "Refused"
    except OSError:
        result["starttls"] = "Blocked"
    except Exception:
        result["starttls"] = "Error"

    return result


# ═══════════════════════════════════════════════════════════════
# Layer 3: Mail Platform Fingerprinting
# ═══════════════════════════════════════════════════════════════

def fingerprint_platform(mx_host, domain):
    if not mx_host:
        return "No MX"
    mx_lower = mx_host.lower()
    for platform, patterns in PLATFORM_PATTERNS:
        for pat in patterns:
            if pat in mx_lower:
                return platform
    dom_parts = domain.lower().split(".")
    if any(p in mx_lower for p in dom_parts if len(p) > 3):
        return "Self-hosted"
    return "Other"


# ═══════════════════════════════════════════════════════════════
# Layer 4: SPF Chain Analysis
# ═══════════════════════════════════════════════════════════════

def walk_spf(domain, depth=0, visited=None):
    if visited is None:
        visited = set()
    if domain in visited or depth > 10:
        return 0, 0, depth, []
    visited.add(domain)

    lookups = 0
    void_lookups = 0
    max_depth = depth
    dangling = []

    try:
        r = make_resolver()
        answers = r.resolve(domain, "TXT")
        spf_txt = ""
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.lower().startswith("v=spf1"):
                spf_txt = txt
                break
        if not spf_txt:
            void_lookups += 1
            return 0, void_lookups, depth, []

        for part in spf_txt.split():
            pl = part.lower()
            if pl.startswith("include:"):
                inc = pl.split(":", 1)[1]
                lookups += 1
                try:
                    sl, sv, sd, sdn = walk_spf(inc, depth + 1, visited)
                    lookups += sl
                    void_lookups += sv
                    max_depth = max(max_depth, sd)
                    dangling.extend(sdn)
                except Exception:
                    dangling.append(inc)
                    void_lookups += 1
            elif pl.startswith("redirect="):
                redir = pl.split("=", 1)[1]
                lookups += 1
                try:
                    sl, sv, sd, sdn = walk_spf(redir, depth + 1, visited)
                    lookups += sl
                    void_lookups += sv
                    max_depth = max(max_depth, sd)
                    dangling.extend(sdn)
                except Exception:
                    dangling.append(redir)
                    void_lookups += 1
            elif pl in ("a", "mx", "ptr") or pl.startswith(("a:", "a/", "mx:", "mx/", "ptr:", "exists:")):
                lookups += 1

    except dns.resolver.NXDOMAIN:
        dangling.append(domain)
        void_lookups += 1
    except Exception:
        void_lookups += 1

    return lookups, void_lookups, max_depth, dangling


def analyze_spf_chain(domain):
    try:
        lookups, void_lookups, depth, dangling = walk_spf(domain)
        return {
            "spf_lookups": lookups,
            "spf_void_lookups": void_lookups,
            "spf_exceeds_limit": lookups > 10,
            "spf_void_exceeds": void_lookups > 2,
            "spf_dangling": dangling,
            "spf_chain_depth": depth,
        }
    except Exception:
        return {
            "spf_lookups": 0, "spf_void_lookups": 0,
            "spf_exceeds_limit": False, "spf_void_exceeds": False,
            "spf_dangling": [], "spf_chain_depth": 0,
        }


# ═══════════════════════════════════════════════════════════════
# Layer 5: Transport Security (MTA-STS, DANE)
# ═══════════════════════════════════════════════════════════════

def check_mta_sts(domain):
    try:
        r = make_resolver()
        answers = r.resolve(f"_mta-sts.{domain}", "TXT")
        for rdata in answers:
            if "v=STSv1" in rdata.to_text():
                return True
    except Exception:
        pass
    return False


def check_dane(mx_host):
    if not mx_host:
        return False
    try:
        r = make_resolver()
        answers = r.resolve(f"_25._tcp.{mx_host}", "TLSA")
        return len(answers) > 0
    except Exception:
        return False


def check_bimi(domain):
    try:
        r = make_resolver()
        answers = r.resolve(f"default._bimi.{domain}", "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if "v=BIMI1" in txt.upper():
                return {"present": True, "record": txt}
    except Exception:
        pass
    return {"present": False, "record": ""}


def check_rbl(mx_host):
    if not mx_host:
        return {"listed": [], "checked": 0}
    try:
        r = make_resolver()
        try:
            answers = r.resolve(mx_host, "A")
            ip = str(answers[0])
        except Exception:
            return {"listed": [], "checked": 0}

        reversed_ip = ".".join(ip.split(".")[::-1])
        listed = []
        for zone in RBL_ZONES:
            try:
                r.resolve(f"{reversed_ip}.{zone}", "A")
                listed.append(zone)
            except Exception:
                pass
        return {"listed": listed, "checked": len(RBL_ZONES)}
    except Exception:
        return {"listed": [], "checked": 0}


def check_fcrdns(mx_host):
    if not mx_host:
        return {"ptr": "", "verified": False}
    try:
        r = make_resolver()
        a_answers = r.resolve(mx_host, "A")
        ip = str(a_answers[0])
        rev = ".".join(ip.split(".")[::-1]) + ".in-addr.arpa"
        ptr_answers = r.resolve(rev, "PTR")
        ptr_name = str(ptr_answers[0]).rstrip(".")
        try:
            fwd_answers = r.resolve(ptr_name, "A")
            fwd_ips = [str(a) for a in fwd_answers]
            return {"ptr": ptr_name, "verified": ip in fwd_ips, "ip": ip}
        except Exception:
            return {"ptr": ptr_name, "verified": False, "ip": ip}
    except Exception:
        return {"ptr": "", "verified": False, "ip": ""}


def check_tls_rpt(domain):
    try:
        r = make_resolver()
        answers = r.resolve(f"_smtp._tls.{domain}", "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if "v=TLSRPTv1" in txt.upper():
                return {"present": True, "record": txt}
    except Exception:
        pass
    return {"present": False, "record": ""}


# ═══════════════════════════════════════════════════════════════
# Layer 6: Composite Score
# ═══════════════════════════════════════════════════════════════

SCORE_WEIGHTS = {
    "dmarc":  {"reject": 30, "quarantine": 15, "none": 5, "missing": 0},
    "spf":    {"hardfail": 20, "softfail": 15, "neutral": 5, "permissive": 0, "missing": 0, "present": 10},
    "dkim":   15,
    "tls":    {"TLSv1.3": 15, "TLSv1.2": 10, "TLSv1.1": 5, "TLSv1": 2},
    "mta_sts": 10,
    "dane":    10,
    "spf_exceed_penalty": -5,
    "spf_void_penalty": -3,
    "rbl_penalty": -10,
    "sp_mismatch_penalty": -5,
    "permissive_spf_penalty": -10,
}

def compute_score(result):
    score = 0

    score += SCORE_WEIGHTS["dmarc"].get(result["dmarc"]["dmarc_policy"], 0)
    score += SCORE_WEIGHTS["spf"].get(result["spf"]["spf_mechanism"], 0)

    if result["spf"]["spf_mechanism"] == "permissive":
        score += SCORE_WEIGHTS["permissive_spf_penalty"]

    if result["spf_chain"]["spf_exceeds_limit"]:
        score += SCORE_WEIGHTS["spf_exceed_penalty"]

    if result["spf_chain"].get("spf_void_exceeds"):
        score += SCORE_WEIGHTS["spf_void_penalty"]

    if result["dkim"]["dkim_found"]:
        score += SCORE_WEIGHTS["dkim"]

    tls_ver = result["smtp"]["tls_version"]
    for pattern, pts in SCORE_WEIGHTS["tls"].items():
        if pattern in tls_ver:
            score += pts
            break

    if result["mta_sts"]:
        score += SCORE_WEIGHTS["mta_sts"]
    if result["dane"]:
        score += SCORE_WEIGHTS["dane"]

    if result.get("rbl", {}).get("listed"):
        score += SCORE_WEIGHTS["rbl_penalty"]

    if result.get("sp_mismatch"):
        score += SCORE_WEIGHTS["sp_mismatch_penalty"]

    score = max(0, min(100, score))

    if score >= 80:   grade = "A"
    elif score >= 60: grade = "B"
    elif score >= 40: grade = "C"
    elif score >= 20: grade = "D"
    else:             grade = "F"

    return score, grade


# ═══════════════════════════════════════════════════════════════
# Full Domain Scan
# ═══════════════════════════════════════════════════════════════

def scan_domain(domain):
    domain = domain.strip().lower().rstrip(".")
    result = {"domain": domain}

    result["mx"] = check_mx(domain)
    result["spf"] = check_spf(domain)
    result["dmarc"] = check_dmarc(domain)

    mx_host = result["mx"]["mx_primary"]
    result["platform"] = fingerprint_platform(mx_host, domain)

    result["dkim"] = check_dkim(domain, result["platform"])

    result["smtp"] = probe_smtp(mx_host)

    result["spf_chain"] = analyze_spf_chain(domain)

    result["mta_sts"] = check_mta_sts(domain)
    result["dane"] = check_dane(mx_host)
    result["bimi"] = check_bimi(domain)
    result["tls_rpt"] = check_tls_rpt(domain)
    result["rbl"] = check_rbl(mx_host)
    result["fcrdns"] = check_fcrdns(mx_host)

    dmarc_sp = result["dmarc"].get("dmarc_sp", "")
    dmarc_p = result["dmarc"]["dmarc_policy"]
    result["sp_mismatch"] = (
        dmarc_p in ("reject", "quarantine") and dmarc_sp == "none"
    )

    score, grade = compute_score(result)
    result["score"] = score
    result["grade"] = grade

    spoofable = result["dmarc"]["dmarc_policy"] in ("none", "missing")
    result["spoofable"] = spoofable

    result["remediation"] = generate_remediation(result)

    return result


# ═══════════════════════════════════════════════════════════════
# Remediation Generator
# ═══════════════════════════════════════════════════════════════

def generate_remediation(result):
    fixes = []
    domain = result["domain"]

    pol = result["dmarc"]["dmarc_policy"]
    if pol == "missing":
        fixes.append({
            "priority": "CRITICAL",
            "issue": "No DMARC record. Domain is fully spoofable.",
            "fix": f"Add TXT record at _dmarc.{domain}",
            "record": f"v=DMARC1; p=reject; rua=mailto:dmarc-reports@{domain}; adkim=s; aspf=s",
        })
    elif pol == "none":
        fixes.append({
            "priority": "CRITICAL",
            "issue": "DMARC policy is p=none (monitor only). Domain is spoofable.",
            "fix": f"Update _dmarc.{domain} to enforce",
            "record": f"v=DMARC1; p=reject; rua=mailto:dmarc-reports@{domain}; adkim=s; aspf=s",
        })
    elif pol == "quarantine":
        fixes.append({
            "priority": "HIGH",
            "issue": "DMARC policy is p=quarantine. Spoofed emails go to spam but are not blocked.",
            "fix": f"Upgrade _dmarc.{domain} to p=reject",
            "record": result["dmarc"]["dmarc_record"].replace("p=quarantine", "p=reject"),
        })

    if result["spf"]["spf_mechanism"] == "missing":
        fixes.append({
            "priority": "HIGH",
            "issue": "No SPF record.",
            "fix": f"Add TXT record at {domain}",
            "record": "v=spf1 include:<your-mail-provider> -all",
        })

    if not result["dkim"]["dkim_found"]:
        provider = result["platform"]
        if provider == "Google Workspace":
            hint = "Enable DKIM in Google Admin Console > Apps > Google Workspace > Gmail > Authenticate Email"
        elif provider == "Microsoft 365":
            hint = "Enable DKIM in Microsoft 365 Defender > Email & Collaboration > Policies > DKIM"
        else:
            hint = "Generate a DKIM key pair and publish the public key as a TXT record at selector._domainkey." + domain
        fixes.append({"priority": "HIGH", "issue": "No DKIM selector found.", "fix": hint, "record": ""})

    if not result["mta_sts"]:
        fixes.append({
            "priority": "MEDIUM",
            "issue": "No MTA-STS. Mail transport is not encrypted by policy.",
            "fix": f"Add TXT record at _mta-sts.{domain} and host policy at https://mta-sts.{domain}/.well-known/mta-sts.txt",
            "record": "v=STSv1; id=20260725",
        })

    if result["spf_chain"]["spf_exceeds_limit"]:
        fixes.append({
            "priority": "HIGH",
            "issue": f"SPF has {result['spf_chain']['spf_lookups']} DNS lookups (RFC 7208 limit is 10). SPF silently fails.",
            "fix": "Flatten SPF record by replacing include: mechanisms with ip4:/ip6: ranges, or use an SPF flattening service.",
            "record": "",
        })

    if result["spf_chain"]["spf_dangling"]:
        for d in result["spf_chain"]["spf_dangling"]:
            fixes.append({
                "priority": "HIGH",
                "issue": f"SPF includes {d} which resolves to NXDOMAIN (dangling include, potential subdomain takeover).",
                "fix": f"Remove 'include:{d}' from SPF record or re-register the domain.",
                "record": "",
            })

    if result["spf_chain"].get("spf_void_exceeds"):
        fixes.append({
            "priority": "HIGH",
            "issue": f"SPF has {result['spf_chain']['spf_void_lookups']} void lookups (RFC 7208 §4.6.4 limit is 2). SPF may PermError.",
            "fix": "Fix or remove broken include: targets that return NXDOMAIN or empty responses.",
            "record": "",
        })

    if result["spf"]["spf_mechanism"] == "permissive":
        fixes.append({
            "priority": "CRITICAL",
            "issue": "SPF uses +all (pass all), allowing ANY IP to send as this domain.",
            "fix": f"Change +all to -all in SPF record at {domain}",
            "record": "",
        })

    if result.get("sp_mismatch"):
        fixes.append({
            "priority": "HIGH",
            "issue": f"DMARC sp=none with p={result['dmarc']['dmarc_policy']}. Subdomains remain spoofable.",
            "fix": f"Set sp=reject in _dmarc.{domain} to protect subdomains",
            "record": "",
        })

    if result.get("rbl", {}).get("listed"):
        zones = result["rbl"]["listed"]
        fixes.append({
            "priority": "HIGH",
            "issue": f"MX server IP is listed on {len(zones)} blocklist(s): {', '.join(zones[:3])}",
            "fix": "Request delisting from each RBL. Investigate and stop spam/abuse from this IP.",
            "record": "",
        })

    return fixes


# ═══════════════════════════════════════════════════════════════
# Output Formatting
# ═══════════════════════════════════════════════════════════════

GRADE_COLOR = {"A": "\033[92m", "B": "\033[96m", "C": "\033[93m", "D": "\033[91m", "F": "\033[31m"}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

def fmt_bool(val):
    return f"\033[92mYes{RESET}" if val else f"\033[91mNo{RESET}"

def fmt_policy(pol):
    if pol == "reject":     return f"\033[92mreject{RESET}"
    if pol == "quarantine": return f"\033[93mquarantine{RESET}"
    if pol == "none":       return f"\033[91mnone (SPOOFABLE){RESET}"
    return f"\033[91mmissing (SPOOFABLE){RESET}"


def print_report(r):
    gc = GRADE_COLOR.get(r["grade"], "")
    print(f"\n{'='*60}")
    print(f"  {BOLD}{r['domain']}{RESET}")
    print(f"  Score: {gc}{BOLD}{r['score']}/100  Grade {r['grade']}{RESET}")
    if r["spoofable"]:
        print(f"  \033[91m{BOLD}*** SPOOFABLE ***{RESET}")
    print(f"{'='*60}")

    print(f"\n  {BOLD}Layer 1: DNS Authentication{RESET}")
    print(f"    MX Record     : {fmt_bool(r['mx']['has_mx'])}", end="")
    if r["mx"]["mx_primary"]:
        print(f"  ({r['mx']['mx_primary']})")
    else:
        print()
    print(f"    SPF            : {r['spf']['spf_mechanism']}", end="")
    if r["spf"]["spf_record"]:
        rec = r["spf"]["spf_record"]
        print(f"  ({rec[:70]}{'...' if len(rec)>70 else ''})")
    else:
        print()
    print(f"    DMARC Policy   : {fmt_policy(r['dmarc']['dmarc_policy'])}")
    if r["dmarc"]["dmarc_rua"]:
        print(f"    DMARC Reporting: {r['dmarc']['dmarc_rua'][:60]}")
    dkim_sels = r["dkim"]["dkim_selectors"]
    print(f"    DKIM           : {fmt_bool(r['dkim']['dkim_found'])}", end="")
    if dkim_sels:
        print(f"  (selectors: {', '.join(dkim_sels)})")
    else:
        print()

    print(f"\n  {BOLD}Layer 2: SMTP/TLS{RESET}")
    print(f"    STARTTLS       : {r['smtp']['starttls']}")
    print(f"    TLS Version    : {r['smtp']['tls_version'] or 'N/A'}")
    print(f"    Cipher Suite   : {r['smtp']['tls_cipher'] or 'N/A'}")

    print(f"\n  {BOLD}Layer 3: Mail Platform{RESET}")
    print(f"    Platform       : {r['platform']}")

    print(f"\n  {BOLD}Layer 4: SPF Chain{RESET}")
    ch = r["spf_chain"]
    exceed = f"\033[91mYes (EXCEEDS RFC 7208 LIMIT){RESET}" if ch["spf_exceeds_limit"] else "\033[92mNo\033[0m"
    print(f"    DNS Lookups    : {ch['spf_lookups']}/10  Exceeds limit: {exceed}")
    void_ex = f"\033[91mYes (EXCEEDS RFC 7208 §4.6.4 LIMIT){RESET}" if ch.get("spf_void_exceeds") else "\033[92mNo\033[0m"
    print(f"    Void Lookups   : {ch.get('spf_void_lookups', 0)}/2   Exceeds limit: {void_ex}")
    print(f"    Chain Depth    : {ch['spf_chain_depth']}")
    if ch["spf_dangling"]:
        print(f"    \033[91mDangling includes: {', '.join(ch['spf_dangling'])}{RESET}")

    print(f"\n  {BOLD}Layer 5: Transport & Reputation{RESET}")
    print(f"    MTA-STS        : {fmt_bool(r['mta_sts'])}")
    print(f"    DANE/TLSA      : {fmt_bool(r['dane'])}")
    print(f"    BIMI           : {fmt_bool(r['bimi']['present'])}")
    print(f"    TLS-RPT        : {fmt_bool(r['tls_rpt']['present'])}")
    fcr = r.get("fcrdns", {})
    if fcr.get("ptr"):
        verified_str = f"\033[92mVerified{RESET}" if fcr["verified"] else f"\033[91mMismatch{RESET}"
        print(f"    FCrDNS         : {fcr['ptr']} ({verified_str})")
    else:
        print(f"    FCrDNS         : \033[91mNo PTR{RESET}")
    rbl = r.get("rbl", {})
    if rbl.get("listed"):
        print(f"    RBL Blocklist   : \033[91mLISTED on {len(rbl['listed'])} zone(s): {', '.join(rbl['listed'][:3])}{RESET}")
    elif rbl.get("checked"):
        print(f"    RBL Blocklist   : \033[92mClean ({rbl['checked']} zones checked){RESET}")
    if r.get("sp_mismatch"):
        print(f"    \033[91mWARNING: sp=none with p={r['dmarc']['dmarc_policy']} — subdomains are spoofable!{RESET}")

    print(f"\n  {BOLD}Layer 6: Composite Score Breakdown{RESET}")
    w = SCORE_WEIGHTS
    dmarc_pts = w["dmarc"].get(r["dmarc"]["dmarc_policy"], 0)
    spf_pts = w["spf"].get(r["spf"]["spf_mechanism"], 0)
    dkim_pts = w["dkim"] if r["dkim"]["dkim_found"] else 0
    tls_pts = 0
    for pat, pts in w["tls"].items():
        if pat in r["smtp"]["tls_version"]:
            tls_pts = pts; break
    mta_pts = w["mta_sts"] if r["mta_sts"] else 0
    dane_pts = w["dane"] if r["dane"] else 0
    spf_pen = w["spf_exceed_penalty"] if ch["spf_exceeds_limit"] else 0

    perm_pen = w["permissive_spf_penalty"] if r["spf"]["spf_mechanism"] == "permissive" else 0
    void_pen = w["spf_void_penalty"] if ch.get("spf_void_exceeds") else 0
    rbl_pen = w["rbl_penalty"] if r.get("rbl", {}).get("listed") else 0
    sp_pen = w["sp_mismatch_penalty"] if r.get("sp_mismatch") else 0

    print(f"    DMARC          : {dmarc_pts:+3d}/30  (p={r['dmarc']['dmarc_policy']})")
    print(f"    SPF            : {spf_pts:+3d}/20  ({r['spf']['spf_mechanism']})")
    if spf_pen:
        print(f"    SPF lookup pen : {spf_pen:+3d}     (exceeds 10-lookup limit)")
    if void_pen:
        print(f"    SPF void pen   : {void_pen:+3d}     (>2 void lookups, RFC 7208)")
    if perm_pen:
        print(f"    SPF +all pen   : {perm_pen:+3d}     (+all allows ANY sender)")
    print(f"    DKIM           : {dkim_pts:+3d}/15")
    print(f"    TLS            : {tls_pts:+3d}/15  ({r['smtp']['tls_version'] or 'none'})")
    print(f"    MTA-STS        : {mta_pts:+3d}/10")
    print(f"    DANE/TLSA      : {dane_pts:+3d}/10")
    if rbl_pen:
        print(f"    RBL penalty    : {rbl_pen:+3d}     (blocklisted)")
    if sp_pen:
        print(f"    sp= mismatch   : {sp_pen:+3d}     (sp=none weakens subdomain protection)")
    total = dmarc_pts + spf_pts + dkim_pts + tls_pts + mta_pts + dane_pts + spf_pen + void_pen + perm_pen + rbl_pen + sp_pen
    total = max(0, min(100, total))
    print(f"    {'─'*30}")
    print(f"    {BOLD}TOTAL          : {total:3d}/100  Grade {r['grade']}{RESET}")

    if r["spoofable"]:
        print(f"\n  \033[41m\033[97m  ⚠  SPOOFABLE — This domain can be impersonated via email  \033[0m")
    else:
        print(f"\n  \033[42m\033[97m  ✓  PROTECTED — DMARC enforcement blocks email spoofing  \033[0m")

    if r.get("remediation"):
        print(f"\n  {BOLD}Remediation{RESET}")
        for fix in r["remediation"]:
            color = "\033[91m" if fix["priority"] == "CRITICAL" else "\033[93m" if fix["priority"] == "HIGH" else "\033[96m"
            print(f"    {color}[{fix['priority']}]{RESET} {fix['issue']}")
            print(f"             {DIM}{fix['fix']}{RESET}")
            if fix["record"]:
                print(f"             Record: {BOLD}{fix['record']}{RESET}")
    print()


def result_to_flat(r):
    return {
        "domain": r["domain"],
        "score": r["score"],
        "grade": r["grade"],
        "spoofable": "Yes" if r["spoofable"] else "No",
        "has_mx": "Yes" if r["mx"]["has_mx"] else "No",
        "mx_primary": r["mx"]["mx_primary"] or "",
        "spf_mechanism": r["spf"]["spf_mechanism"],
        "spf_record": r["spf"]["spf_record"],
        "dmarc_policy": r["dmarc"]["dmarc_policy"],
        "dmarc_record": r["dmarc"]["dmarc_record"],
        "dmarc_rua": r["dmarc"]["dmarc_rua"],
        "dkim_found": "Yes" if r["dkim"]["dkim_found"] else "No",
        "dkim_selectors": "; ".join(r["dkim"]["dkim_selectors"]),
        "starttls": r["smtp"]["starttls"],
        "tls_version": r["smtp"]["tls_version"],
        "tls_cipher": r["smtp"]["tls_cipher"],
        "platform": r["platform"],
        "spf_lookups": r["spf_chain"]["spf_lookups"],
        "spf_void_lookups": r["spf_chain"].get("spf_void_lookups", 0),
        "spf_exceeds_limit": "Yes" if r["spf_chain"]["spf_exceeds_limit"] else "No",
        "spf_void_exceeds": "Yes" if r["spf_chain"].get("spf_void_exceeds") else "No",
        "spf_dangling": "; ".join(r["spf_chain"]["spf_dangling"]),
        "spf_chain_depth": r["spf_chain"]["spf_chain_depth"],
        "mta_sts": "Yes" if r["mta_sts"] else "No",
        "dane_tlsa": "Yes" if r["dane"] else "No",
        "bimi": "Yes" if r["bimi"]["present"] else "No",
        "tls_rpt": "Yes" if r["tls_rpt"]["present"] else "No",
        "rbl_listed": "; ".join(r.get("rbl", {}).get("listed", [])),
        "rbl_clean": "Yes" if not r.get("rbl", {}).get("listed") and r.get("rbl", {}).get("checked") else "No",
        "fcrdns_ptr": r.get("fcrdns", {}).get("ptr", ""),
        "fcrdns_verified": "Yes" if r.get("fcrdns", {}).get("verified") else "No",
        "sp_mismatch": "Yes" if r.get("sp_mismatch") else "No",
        "dkim_wildcard": "Yes" if r.get("dkim", {}).get("dkim_wildcard") else "No",
    }


# ═══════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        prog="spoofscore",
        description="Multi-layer email security scanner. Checks 8 layers and assigns a composite spoofability score (0-100).",
        epilog="https://github.com/harrizuan/spoofscore — License: MIT",
    )
    parser.add_argument("domains", nargs="*", help="Domain(s) to scan")
    parser.add_argument("-f", "--file", help="File with one domain per line")
    parser.add_argument("-o", "--output", help="Output CSV file path")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of human-readable report")
    parser.add_argument("--smtp-threads", type=int, default=10, help="SMTP probing threads for batch mode (default: 10)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args()

    domains = list(args.domains) if args.domains else []
    if args.file:
        with open(args.file) as fh:
            domains.extend(line.strip() for line in fh if line.strip() and not line.startswith("#"))

    if not domains:
        parser.print_help()
        sys.exit(1)

    domains = list(dict.fromkeys(domains))

    if not args.json:
        print(f"\n  SpoofScore v{__version__}")
        print(f"  Scanning {len(domains)} domain{'s' if len(domains)>1 else ''}...\n")

    results = []
    for i, domain in enumerate(domains):
        if not args.json:
            print(f"  [{i+1}/{len(domains)}] {domain}...", flush=True)
        r = scan_domain(domain)
        results.append(r)
        if not args.json:
            print_report(r)

    if args.json:
        out = []
        for r in results:
            flat = result_to_flat(r)
            flat["spf_dangling"] = r["spf_chain"]["spf_dangling"]
            flat["dkim_selectors"] = r["dkim"]["dkim_selectors"]
            flat["mx_all"] = r["mx"]["mx_all"]
            if r.get("remediation"):
                flat["remediation"] = r["remediation"]
            out.append(flat)
        print(json.dumps(out, indent=2))

    if args.output:
        fieldnames = list(result_to_flat(results[0]).keys())
        with open(args.output, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                writer.writerow(result_to_flat(r))
        if not args.json:
            print(f"  Results saved to {args.output}")

    if not args.json and len(results) > 1:
        scores = [r["score"] for r in results]
        avg = sum(scores) / len(scores)
        spoofable = sum(1 for r in results if r["spoofable"])
        print(f"\n{'='*60}")
        print(f"  SUMMARY: {len(results)} domains scanned")
        print(f"  Average score: {avg:.1f}/100")
        print(f"  Spoofable: {spoofable}/{len(results)} ({spoofable/len(results)*100:.0f}%)")
        print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
