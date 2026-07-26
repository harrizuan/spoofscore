#!/usr/bin/env python3
"""
SpoofScore — Multi-Layer Email Security Scanner

Scans any domain across 9 security layers and produces a composite score (0-100).
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
    9. Routing Risk        — Ghost-Sender detection: indirect MX to Exchange Online

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

__version__ = "2.1.0"

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
# Layer 9: Routing Risk Analysis (Ghost-Sender Detection)
# ═══════════════════════════════════════════════════════════════

def check_routing_risk(domain, mx_host):
    """Detect indirect MX routing to Exchange Online (Ghost-Sender risk).
    If MX points to a third-party gateway but an Exchange Online tenant
    endpoint exists, attackers can deliver spoofed mail directly to the
    tenant, bypassing the security gateway and all authentication."""
    result = {"indirect_mx": False, "eol_endpoint": "", "risk": "", "mx_target": ""}
    if not mx_host:
        return result

    mx_lower = mx_host.lower()

    if "protection.outlook.com" in mx_lower:
        return result

    eol_host = domain.replace(".", "-") + ".mail.protection.outlook.com"
    try:
        r = make_resolver()
        r.resolve(eol_host, "A")
        result["indirect_mx"] = True
        result["eol_endpoint"] = eol_host
        result["mx_target"] = mx_host
        result["risk"] = (
            f"MX routes to {mx_host} but Exchange Online endpoint "
            f"{eol_host} is directly accessible. Ghost-Sender risk: "
            f"spoofed mail can bypass the security gateway entirely."
        )
    except Exception:
        pass

    return result


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
    "routing_risk_penalty": -5,
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

    if result.get("routing_risk", {}).get("indirect_mx"):
        score += SCORE_WEIGHTS["routing_risk_penalty"]

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

def scan_domain(domain, json_mode=False):
    domain = domain.strip().lower().rstrip(".")
    result = {"domain": domain}
    t0 = time.time()

    show_progress(domain, 0, total_steps=9, json_mode=json_mode)
    result["mx"] = check_mx(domain)
    result["spf"] = check_spf(domain)
    result["dmarc"] = check_dmarc(domain)

    show_progress(domain, 1, total_steps=9, json_mode=json_mode)
    mx_host = result["mx"]["mx_primary"]
    result["platform"] = fingerprint_platform(mx_host, domain)

    show_progress(domain, 2, total_steps=9, json_mode=json_mode)
    result["dkim"] = check_dkim(domain, result["platform"])

    show_progress(domain, 3, total_steps=9, json_mode=json_mode)
    result["smtp"] = probe_smtp(mx_host)

    show_progress(domain, 4, total_steps=9, json_mode=json_mode)
    result["spf_chain"] = analyze_spf_chain(domain)

    show_progress(domain, 5, total_steps=9, json_mode=json_mode)
    result["mta_sts"] = check_mta_sts(domain)
    result["dane"] = check_dane(mx_host)
    result["bimi"] = check_bimi(domain)
    result["tls_rpt"] = check_tls_rpt(domain)

    show_progress(domain, 6, total_steps=9, json_mode=json_mode)
    result["rbl"] = check_rbl(mx_host)
    result["fcrdns"] = check_fcrdns(mx_host)

    show_progress(domain, 7, total_steps=9, json_mode=json_mode)
    dmarc_sp = result["dmarc"].get("dmarc_sp", "")
    dmarc_p = result["dmarc"]["dmarc_policy"]
    result["sp_mismatch"] = (
        dmarc_p in ("reject", "quarantine") and dmarc_sp == "none"
    )

    show_progress(domain, 8, total_steps=9, json_mode=json_mode)
    result["routing_risk"] = check_routing_risk(domain, mx_host)

    score, grade = compute_score(result)
    result["score"] = score
    result["grade"] = grade

    spoofable = result["dmarc"]["dmarc_policy"] in ("none", "missing")
    result["spoofable"] = spoofable

    result["remediation"] = generate_remediation(result)
    result["scan_time"] = time.time() - t0

    if not json_mode:
        clear_progress()

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

    rr = result.get("routing_risk", {})
    if rr.get("indirect_mx"):
        fixes.append({
            "priority": "CRITICAL",
            "issue": f"Ghost-Sender risk: MX routes to {rr.get('mx_target', 'third-party')} but Exchange Online endpoint {rr.get('eol_endpoint', '')} is directly accessible.",
            "fix": (
                "Point MX directly to Exchange Online (*.mail.protection.outlook.com), "
                "or configure Exchange Online to reject inbound mail not originating from "
                "your security gateway's IP range using Connector + Enhanced Filtering."
            ),
            "record": "",
        })

    return fixes


# ═══════════════════════════════════════════════════════════════
# Output Formatting
# ═══════════════════════════════════════════════════════════════

R  = "\033[0m"
B  = "\033[1m"
DM = "\033[2m"
UL = "\033[4m"
RD = "\033[91m"
GR = "\033[92m"
YL = "\033[93m"
BL = "\033[94m"
MG = "\033[95m"
CY = "\033[96m"
WH = "\033[97m"
BG_RD = "\033[41m"
BG_GR = "\033[42m"
BG_YL = "\033[43m"
BG_BL = "\033[44m"
BG_DK = "\033[48;5;236m"

GRADE_STYLE = {
    "A": (GR, "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓"),
    "B": (CY, "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░"),
    "C": (YL, "▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░"),
    "D": (RD, "▓▓▓▓▓▓▓▓░░░░░░░░░░░░"),
    "F": (RD, "▓▓▓▓░░░░░░░░░░░░░░░░"),
}

BANNER = f"""
{CY}  .-')     _ (`-.                                        .-')                           _  .-')     ('-.{R}
{CY} ( OO ).  ( (OO  )                                      ( OO ).                        ( \\( -O )  _(  OO){R}
{CY}(_)---\\_)_.`     \\ .-'),-----.  .-'),-----.    ,------.(_)---\\_)   .-----.  .-'),-----. ,------. (,------.{R}
{CY}/    _ |(__...--''( OO'  .-.  '( OO'  .-.  '('-| _.---'/    _ |   '  .--./ ( OO'  .-.  '|   /`. ' |  .---'{R}
{CY}\\  :` `. |  /  | |/   |  | |  |/   |  | |  |(OO|(_\\    \\  :` `.   |  |('-. /   |  | |  ||  /  | | |  |{R}
{CY} '..`''.)|  |_.' |\\_) |  |\\|  |\\_) |  |\\|  |/  |  '--.  '..`''.) /_) |OO  )\\_) |  |\\|  ||  |_.' |(|  '--.{R}
{CY}.-._)   \\|  .___.'  \\ |  | |  |  \\ |  | |  |\\_)|  .--' .-._)   \\ ||  |`-'|   \\ |  | |  ||  .  '.' |  .--'{R}
{CY}\\       /|  |        `'  '-'  '   `'  '-'  '  \\|  |_)  \\       /(_'  '--'\\    `'  '-'  '|  |\\  \\  |  `---.{R}
{CY} `-----' `--'          `-----'      `-----'    `--'     `-----'    `-----'      `-----' `--' '--' `------'{R}

{B}   SpoofScore{R} {DM}v{__version__}{R}    {DM}Can someone impersonate your domain via email?{R}
{DM}   made by {B}bau1u{R} {DM}— github.com/harrizuan/spoofscore{R}
"""

LAYER_NAMES = [
    ("🔐", "DNS Auth"),
    ("📧", "Platform"),
    ("🔑", "DKIM"),
    ("🔒", "SMTP/TLS"),
    ("🔗", "SPF Chain"),
    ("🛡️ ", "Transport"),
    ("📡", "Reputation"),
    ("⚙️ ", "Scoring"),
    ("🔀", "Routing"),
]

def show_progress(domain, step, total_steps=9, json_mode=False):
    if json_mode:
        return
    icon, name = LAYER_NAMES[step] if step < len(LAYER_NAMES) else ("⚙️ ", "Scoring")
    filled = round((step + 1) / total_steps * 16)
    bar = f"{CY}{'█' * filled}{'░' * (16 - filled)}{R}"
    print(f"\r   {bar} {icon}  {DM}{name:<12}{R}", end="", flush=True)

def clear_progress():
    print(f"\r{'':>60}\r", end="", flush=True)

def fmt_time(seconds):
    if seconds < 1:
        return f"{seconds*1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    m, s = divmod(seconds, 60)
    return f"{int(m)}m{s:.0f}s"

def score_bar(score, width=20):
    filled = round(score / 100 * width)
    empty = width - filled
    color, _ = GRADE_STYLE.get(
        "A" if score >= 80 else "B" if score >= 60 else "C" if score >= 40 else "D" if score >= 20 else "F",
        (CY, "")
    )
    return f"{color}{'█' * filled}{DM}{'░' * empty}{R}"

def dot(ok):
    return f"{GR}●{R}" if ok else f"{RD}●{R}"

def tag(ok):
    return f"{GR}✓{R}" if ok else f"{RD}✗{R}"

def fmt_policy(pol):
    if pol == "reject":     return f"{GR}{B}reject{R}"
    if pol == "quarantine": return f"{YL}{B}quarantine{R}"
    if pol == "none":       return f"{RD}{B}none{R} {DM}(monitor only){R}"
    return f"{RD}{B}missing{R}"

def fmt_spf(mech):
    if mech == "hardfail":   return f"{GR}{B}-all{R} {DM}(hardfail){R}"
    if mech == "softfail":   return f"{YL}{B}~all{R} {DM}(softfail){R}"
    if mech == "permissive": return f"{RD}{B}+all{R} {DM}(PERMISSIVE){R}"
    if mech == "neutral":    return f"{YL}{B}?all{R} {DM}(neutral){R}"
    if mech == "present":    return f"{YL}present{R}"
    return f"{RD}{B}missing{R}"

def section(icon, title):
    print(f"\n   {CY}┌{'─'*52}┐{R}")
    print(f"   {CY}│{R} {icon}  {B}{WH}{title}{R}")
    print(f"   {CY}└{'─'*52}┘{R}")

def row(label, value, extra=""):
    label_padded = f"{label:<16}"
    extra_str = f"  {DM}{extra}{R}" if extra else ""
    print(f"      {DM}{label_padded}{R} {value}{extra_str}")

def print_report(r, elapsed=0):
    ch = r["spf_chain"]
    w = SCORE_WEIGHTS
    score = r["score"]
    grade = r["grade"]
    gc, _ = GRADE_STYLE.get(grade, (CY, ""))

    time_str = f" {DM}({fmt_time(elapsed)}){R}" if elapsed else ""
    print(f"\n   {CY}{'━' * 54}{R}")
    print(f"   {B}{WH}{r['domain']}{R}{time_str}")
    print()
    print(f"      Score    {score_bar(score)}  {gc}{B}{score}/100{R}")
    print(f"      Grade    {gc}{B}{'▌' * 3} {grade} {'▐' * 3}{R}")
    if r["spoofable"]:
        print(f"      Verdict  {RD}{B}⚠ SPOOFABLE{R}")
    else:
        print(f"      Verdict  {GR}{B}✓ PROTECTED{R}")
    print(f"   {CY}{'━' * 54}{R}")

    # Layer 1: DNS Authentication
    section("🔐", "Layer 1 — DNS Authentication")
    row("MX Record", tag(r["mx"]["has_mx"]),
        r["mx"]["mx_primary"] or "no MX")
    row("SPF", fmt_spf(r["spf"]["spf_mechanism"]))
    if r["spf"]["spf_record"]:
        rec = r["spf"]["spf_record"]
        print(f"      {DM}{'':>16} {rec[:60]}{'...' if len(rec)>60 else ''}{R}")
    row("DMARC", fmt_policy(r["dmarc"]["dmarc_policy"]))
    if r["dmarc"]["dmarc_rua"]:
        row("Reporting", f"{DM}{r['dmarc']['dmarc_rua'][:55]}{R}")
    dkim_sels = r["dkim"]["dkim_selectors"]
    row("DKIM", tag(r["dkim"]["dkim_found"]),
        f"selectors: {', '.join(dkim_sels)}" if dkim_sels else "none found")
    if r["dkim"].get("dkim_wildcard"):
        print(f"      {YL}{'':>16} ⚠ Wildcard _domainkey detected (catch-all){R}")

    # Layer 2: SMTP/TLS
    section("🔒", "Layer 2 — SMTP/TLS Probing")
    starttls_val = r["smtp"]["starttls"]
    if starttls_val == "Yes":
        row("STARTTLS", f"{GR}{B}Yes{R}")
    elif starttls_val == "Blocked":
        row("STARTTLS", f"{YL}Blocked{R}", "port 25 unreachable")
    else:
        row("STARTTLS", f"{RD}No{R}")
    tls_v = r["smtp"]["tls_version"] or ""
    if "1.3" in tls_v:
        row("TLS Version", f"{GR}{B}{tls_v}{R}")
    elif "1.2" in tls_v:
        row("TLS Version", f"{CY}{tls_v}{R}")
    elif tls_v:
        row("TLS Version", f"{YL}{tls_v}{R}")
    else:
        row("TLS Version", f"{DM}—{R}")
    row("Cipher", f"{r['smtp']['tls_cipher'] or '—'}")

    # Layer 3: Mail Platform
    section("📧", "Layer 3 — Mail Platform")
    plat = r["platform"]
    plat_icons = {
        "Google Workspace": "Google", "Microsoft 365": "Microsoft",
        "Amazon SES": "AWS SES", "ProtonMail": "Proton",
    }
    row("Provider", f"{B}{plat_icons.get(plat, plat)}{R}")

    # Layer 4: SPF Chain
    section("🔗", "Layer 4 — SPF Chain Analysis")
    lookups = ch["spf_lookups"]
    lookup_color = GR if lookups <= 7 else YL if lookups <= 10 else RD
    row("DNS Lookups", f"{lookup_color}{B}{lookups}{R}{DM}/10{R}",
        f"{RD}EXCEEDS RFC 7208{R}" if ch["spf_exceeds_limit"] else "")
    void_c = ch.get("spf_void_lookups", 0)
    void_color = GR if void_c <= 1 else YL if void_c <= 2 else RD
    row("Void Lookups", f"{void_color}{B}{void_c}{R}{DM}/2{R}",
        f"{RD}EXCEEDS §4.6.4{R}" if ch.get("spf_void_exceeds") else "")
    row("Chain Depth", f"{ch['spf_chain_depth']}")
    if ch["spf_dangling"]:
        for dang in ch["spf_dangling"]:
            print(f"      {RD}  ⚠ Dangling: {B}{dang}{R} {DM}(NXDOMAIN — takeover risk){R}")

    # Layer 5: Transport Security
    section("🛡️ ", "Layer 5 — Transport & Reputation")
    row("MTA-STS", tag(r["mta_sts"]), "RFC 8461")
    row("DANE/TLSA", tag(r["dane"]), "RFC 7672")
    row("BIMI", tag(r["bimi"]["present"]))
    row("TLS-RPT", tag(r["tls_rpt"]["present"]))
    fcr = r.get("fcrdns", {})
    if fcr.get("ptr"):
        v = f"{GR}Verified{R}" if fcr["verified"] else f"{RD}Mismatch{R}"
        row("FCrDNS", v, fcr["ptr"])
    else:
        row("FCrDNS", f"{RD}No PTR{R}")
    rbl = r.get("rbl", {})
    if rbl.get("listed"):
        row("RBL Status", f"{RD}{B}LISTED{R}", f"{len(rbl['listed'])} zone(s)")
        for zone in rbl["listed"][:3]:
            print(f"      {RD}{'':>16} ● {zone}{R}")
    elif rbl.get("checked"):
        row("RBL Status", f"{GR}Clean{R}", f"{rbl['checked']} zones scanned")
    if r.get("sp_mismatch"):
        print(f"      {YL}  ⚠ sp=none with p={r['dmarc']['dmarc_policy']}{R} {DM}(subdomains spoofable){R}")

    # Layer 9: Routing Risk
    rr = r.get("routing_risk", {})
    if rr.get("indirect_mx") or rr.get("eol_endpoint"):
        section("🔀", "Layer 9 — Routing Risk Analysis")
        if rr.get("indirect_mx"):
            row("Routing", f"{RD}{B}INDIRECT MX{R}", "Ghost-Sender risk")
            row("MX Target", f"{rr['mx_target']}")
            row("EOL Endpoint", f"{RD}{rr['eol_endpoint']}{R}", "directly accessible")
            print(f"      {RD}  ⚠ Exchange Online tenant accepts direct connections.{R}")
            print(f"      {RD}    Spoofed mail can bypass security gateway entirely.{R}")
        else:
            row("Routing", f"{GR}{B}DIRECT{R}", "MX points to Exchange Online")
    elif r.get("platform") == "Microsoft 365":
        section("🔀", "Layer 9 — Routing Risk Analysis")
        row("Routing", f"{GR}{B}DIRECT{R}", "MX points to Exchange Online")

    # Layer 6: Score Breakdown
    section("📊", "Layer 6 — Score Breakdown")
    dmarc_pts = w["dmarc"].get(r["dmarc"]["dmarc_policy"], 0)
    spf_pts = w["spf"].get(r["spf"]["spf_mechanism"], 0)
    dkim_pts = w["dkim"] if r["dkim"]["dkim_found"] else 0
    tls_pts = 0
    for pat, pts in w["tls"].items():
        if pat in r["smtp"]["tls_version"]:
            tls_pts = pts
            break
    mta_pts = w["mta_sts"] if r["mta_sts"] else 0
    dane_pts = w["dane"] if r["dane"] else 0
    spf_pen = w["spf_exceed_penalty"] if ch["spf_exceeds_limit"] else 0
    perm_pen = w["permissive_spf_penalty"] if r["spf"]["spf_mechanism"] == "permissive" else 0
    void_pen = w["spf_void_penalty"] if ch.get("spf_void_exceeds") else 0
    rbl_pen = w["rbl_penalty"] if r.get("rbl", {}).get("listed") else 0
    sp_pen = w["sp_mismatch_penalty"] if r.get("sp_mismatch") else 0
    route_pen = w["routing_risk_penalty"] if r.get("routing_risk", {}).get("indirect_mx") else 0

    def pts_color(val, maximum):
        if val <= 0: return RD
        return GR if val >= maximum else YL

    def score_row(label, val, maximum, note=""):
        c = pts_color(val, maximum)
        bar_w = 10
        filled = round(abs(val) / maximum * bar_w) if maximum else 0
        bar = f"{c}{'█' * filled}{DM}{'░' * (bar_w - filled)}{R}"
        sign = "+" if val > 0 else " " if val == 0 else ""
        note_str = f"  {DM}{note}{R}" if note else ""
        print(f"      {DM}{label:<14}{R} {bar} {c}{B}{sign}{val}{R}{DM}/{maximum}{R}{note_str}")

    def penalty_row(label, val, note=""):
        if val == 0:
            return
        print(f"      {DM}{label:<14}{R} {'':>10} {RD}{B}{val}{R}    {DM}{note}{R}")

    score_row("DMARC", dmarc_pts, 30, f"p={r['dmarc']['dmarc_policy']}")
    score_row("SPF", spf_pts, 20, r["spf"]["spf_mechanism"])
    score_row("DKIM", dkim_pts, 15)
    score_row("TLS", tls_pts, 15, r["smtp"]["tls_version"] or "none")
    score_row("MTA-STS", mta_pts, 10)
    score_row("DANE/TLSA", dane_pts, 10)
    penalty_row("SPF lookups", spf_pen, ">10 lookups")
    penalty_row("SPF void", void_pen, ">2 void lookups")
    penalty_row("SPF +all", perm_pen, "allows any sender")
    penalty_row("RBL", rbl_pen, "blocklisted")
    penalty_row("sp= mismatch", sp_pen, "subdomain policy gap")
    penalty_row("Routing risk", route_pen, "Ghost-Sender")
    print(f"      {CY}{'─' * 44}{R}")
    total = max(0, min(100, dmarc_pts + spf_pts + dkim_pts + tls_pts + mta_pts + dane_pts + spf_pen + void_pen + perm_pen + rbl_pen + sp_pen + route_pen))
    print(f"      {B}{'TOTAL':<14}{R} {score_bar(total)}  {gc}{B}{total}/100  {grade}{R}")

    # Verdict banner
    print()
    if r["spoofable"]:
        line = "  ⚠  SPOOFABLE — This domain can be impersonated via email  "
        print(f"   {BG_RD}{WH}{B}{line}{R}")
    else:
        line = "  ✓  PROTECTED — DMARC enforcement blocks email spoofing    "
        print(f"   {BG_GR}{WH}{B}{line}{R}")

    # Remediation
    if r.get("remediation"):
        print(f"\n   {CY}┌{'─'*52}┐{R}")
        print(f"   {CY}│{R} 🔧  {B}{WH}Remediation{R}")
        print(f"   {CY}└{'─'*52}┘{R}")
        prio_style = {"CRITICAL": (RD, "◆"), "HIGH": (YL, "▲"), "MEDIUM": (CY, "●"), "LOW": (DM, "○")}
        for fix in r["remediation"]:
            pc, icon = prio_style.get(fix["priority"], (DM, "○"))
            print(f"      {pc}{B}{icon} [{fix['priority']}]{R} {fix['issue']}")
            print(f"      {DM}  → {fix['fix']}{R}")
            if fix["record"]:
                print(f"      {GR}  $ {B}{fix['record']}{R}")
            print()
    else:
        print()
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
        "routing_risk": "Yes" if r.get("routing_risk", {}).get("indirect_mx") else "No",
        "routing_eol_endpoint": r.get("routing_risk", {}).get("eol_endpoint", ""),
    }


# ═══════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        prog="spoofscore",
        description="Multi-layer email security scanner. Checks 9 layers and assigns a composite spoofability score (0-100).",
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
        print(BANNER)
        n = len(domains)
        print(f"   {DM}Scanning {B}{WH}{n}{R}{DM} domain{'s' if n > 1 else ''}...{R}\n")

    total_start = time.time()
    results = []
    for i, domain in enumerate(domains):
        if not args.json:
            print(f"   {DM}[{i+1}/{len(domains)}]{R} {B}{domain}{R}", flush=True)
        r = scan_domain(domain, json_mode=args.json)
        results.append(r)
        if not args.json:
            elapsed = r.get("scan_time", 0)
            print_report(r, elapsed)

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

    total_elapsed = time.time() - total_start

    if not args.json and len(results) > 1:
        scores = [r["score"] for r in results]
        avg = sum(scores) / len(scores)
        spoofable_n = sum(1 for r in results if r["spoofable"])
        protected_n = len(results) - spoofable_n
        spoof_pct = spoofable_n / len(results) * 100
        avg_color = GR if avg >= 80 else CY if avg >= 60 else YL if avg >= 40 else RD
        avg_grade = "A" if avg >= 80 else "B" if avg >= 60 else "C" if avg >= 40 else "D" if avg >= 20 else "F"
        grade_counts = {}
        for rr in results:
            grade_counts[rr["grade"]] = grade_counts.get(rr["grade"], 0) + 1

        print(f"\n   {CY}╔{'═'*54}╗{R}")
        print(f"   {CY}║{R}  {B}{WH}SCAN COMPLETE{R}    {DM}{fmt_time(total_elapsed)}{R}{'':>30}{CY}║{R}")
        print(f"   {CY}╠{'═'*54}╣{R}")
        print(f"   {CY}║{R}                                                      {CY}║{R}")
        print(f"   {CY}║{R}  {DM}Domains{R}       {B}{WH}{len(results)}{R}                                    {CY}║{R}")
        print(f"   {CY}║{R}  {DM}Avg Score{R}     {score_bar(avg)}  {avg_color}{B}{avg:.0f}/100 {avg_grade}{R}    {CY}║{R}")
        print(f"   {CY}║{R}                                                      {CY}║{R}")
        print(f"   {CY}║{R}  {GR}● Protected{R}   {B}{protected_n}{R}                                    {CY}║{R}")
        print(f"   {CY}║{R}  {RD}● Spoofable{R}   {B}{spoofable_n}{R} ({spoof_pct:.0f}%)                             {CY}║{R}")
        print(f"   {CY}║{R}                                                      {CY}║{R}")
        grade_line = "  ".join(f"{GRADE_STYLE.get(g,(CY,''))[0]}{B}{g}{R}:{grade_counts.get(g,0)}" for g in "ABCDF")
        print(f"   {CY}║{R}  {DM}Grades{R}        {grade_line}{'':>10}{CY}║{R}")
        print(f"   {CY}║{R}                                                      {CY}║{R}")
        print(f"   {CY}╚{'═'*54}╝{R}")
        print()
    elif not args.json:
        print(f"   {DM}Completed in {fmt_time(total_elapsed)}{R}\n")


if __name__ == "__main__":
    main()
