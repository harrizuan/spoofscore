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
    1.  DNS Authentication   — MX, SPF, DMARC (with effective policy), DKIM selectors
    2.  DKIM Key Strength    — RSA key size, Ed25519 detection, revoked/dangling keys
    3.  SMTP/TLS Probing     — STARTTLS, TLS version, cipher suite, SMTP banner
    4.  Mail Platform        — Fingerprint MX (Google, Microsoft 365, Proofpoint, etc.)
    5.  SPF Chain Analysis   — Recursive include walk, 10-lookup limit, BreakSPF checks
    6.  Transport Security   — MTA-STS policy fetch, DANE/TLSA, BIMI+VMC, TLS-RPT, DNSSEC
    7.  Reputation           — FCrDNS, expanded RBL (40 zones)
    8.  Policy Analysis      — aspf/adkim alignment, t=y, pct, np, sp, multiple records
    9.  Routing & Supply     — Ghost-Sender, EchoSpoofing, LaunDroMARC, dangling DKIM
    10. Validation           — DMARC EDV, deprecated tags (DMARCbis RFC 9989)
    11. Composite Score      — Interaction-aware weighted scoring with penalty multipliers

Unlike generic email auditors, SpoofScore focuses on real-world spoofability:
"Can someone impersonate this domain?" — not just "is the domain configured correctly?"

New in v3: BreakSPF detection, EchoSpoofing fingerprinting, DKIM key strength,
MTA-STS policy validation, DMARCbis compliance, and 16 new scoring penalties.

Requires: dnspython (pip install dnspython)
Port 25 access required for SMTP probing. If blocked, the score excludes TLS points.

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

__version__ = "3.0.0"

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
    "dnsbl-2.uceprotect.net",
    "dnsbl-3.uceprotect.net",
    "psbl.surriel.com",
    "all.s5h.net",
    "rbl.megarbl.net",
    "combined.abuse.ch",
    "dnsbl.dronebl.org",
    "spam.dnsbl.sorbs.net",
    "http.dnsbl.sorbs.net",
    "socks.dnsbl.sorbs.net",
    "web.dnsbl.sorbs.net",
    "new.spam.dnsbl.sorbs.net",
    "bl.mailspike.net",
    "ix.dnsbl.manitu.net",
    "virus.rbl.jp",
    "access.redhawk.org",
    "blacklist.woody.ch",
    "bogons.cymru.com",
    "db.wpbl.info",
    "dnsbl.kempt.net",
    "orvedb.aupads.org",
    "relays.nether.net",
    "singular.ttk.pte.hu",
    "ubl.lashback.com",
    "dnsbl.spfbl.net",
    "z.mailspike.net",
    "bl.blocklist.de",
    "spam.abuse.ch",
    "bl.0spam.org",
    "dnsrbl.org",
    "rbl.interserver.net",
    "truncate.gbudb.net",
    "spamguard.leadmon.net",
    "dnsbl.rv-soft.info",
    "dnsbl.burnt-tech.com",
]

MULTI_TENANT_INCLUDES = {
    "spf.protection.outlook.com", "_spf.google.com",
    "amazonses.com", "sendgrid.net", "mailgun.org",
    "salesforce.com", "mcsv.net", "mandrillapp.com",
    "hubspotemail.net", "zendesk.com", "freshdesk.com",
    "servers.mcsv.net", "mail.zendesk.com",
    "spf.messagelabs.com", "spf.mailjet.com",
    "spf1.mailhostbox.com", "spf.constantcontact.com",
    "mktomail.com", "stspg-customer.com",
    "sparkpostmail.com", "mtasv.net",
}

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
    result = {
        "spf_record": "", "spf_mechanism": "missing",
        "spf_multiple": False, "spf_syntax_errors": [],
        "spf_has_ptr": False, "spf_multi_tenant_includes": [],
        "spf_wide_cidrs": [],
    }
    try:
        r = make_resolver()
        answers = r.resolve(domain, "TXT")
        spf_records = []
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.lower().startswith("v=spf1"):
                spf_records.append(txt)

        if len(spf_records) > 1:
            result["spf_multiple"] = True

        if spf_records:
            txt = spf_records[0]
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

            for part in txt.split():
                pl = part.lower()
                if pl.startswith("ptr") or pl.startswith("+ptr"):
                    result["spf_has_ptr"] = True
                if pl.startswith("include:"):
                    inc_domain = pl.split(":", 1)[1]
                    for mt in MULTI_TENANT_INCLUDES:
                        if mt in inc_domain:
                            result["spf_multi_tenant_includes"].append(inc_domain)
                            break
                if pl.startswith("ip4:") and "/" in pl:
                    try:
                        prefix = int(pl.rsplit("/", 1)[1])
                        if prefix <= 20:
                            result["spf_wide_cidrs"].append(pl.split(":", 1)[1])
                    except ValueError:
                        pass
                if pl.startswith("ipv4:"):
                    result["spf_syntax_errors"].append(f"'{part}' should be 'ip4:'")
                if pl.startswith("ipv6:"):
                    result["spf_syntax_errors"].append(f"'{part}' should be 'ip6:'")
    except Exception:
        pass
    return result


def check_dmarc(domain):
    result = {
        "dmarc_record": "", "dmarc_policy": "missing",
        "dmarc_sp": "", "dmarc_pct": "", "dmarc_rua": "", "dmarc_ruf": "",
        "dmarc_aspf": "r", "dmarc_adkim": "r",
        "dmarc_np": "", "dmarc_t": "", "dmarc_psd": "",
        "dmarc_deprecated_tags": [],
        "dmarc_multiple": False,
        "dmarc_effective_policy": "missing",
    }
    try:
        r = make_resolver()
        answers = r.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_records = []
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if "v=DMARC1" in txt or "v=dmarc1" in txt.lower():
                dmarc_records.append(txt)

        if len(dmarc_records) > 1:
            result["dmarc_multiple"] = True

        if dmarc_records:
            txt = dmarc_records[0]
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
            result["dmarc_aspf"] = tags.get("aspf", "r")
            result["dmarc_adkim"] = tags.get("adkim", "r")
            result["dmarc_np"] = tags.get("np", "")
            result["dmarc_t"] = tags.get("t", "")
            result["dmarc_psd"] = tags.get("psd", "")

            deprecated = []
            if "pct" in tags:
                deprecated.append("pct")
            if "rf" in tags:
                deprecated.append("rf")
            if "ri" in tags:
                deprecated.append("ri")
            result["dmarc_deprecated_tags"] = deprecated

            p = result["dmarc_policy"]
            pct = tags.get("pct", "")
            t_flag = tags.get("t", "")
            effective = p
            if t_flag == "y":
                if p == "reject":
                    effective = "quarantine"
                elif p == "quarantine":
                    effective = "none"
            elif pct and pct != "100":
                try:
                    pct_val = int(pct)
                    if pct_val == 0:
                        effective = "none"
                    elif pct_val < 100 and p == "reject":
                        effective = "quarantine"
                except ValueError:
                    pass
            result["dmarc_effective_policy"] = effective
    except Exception:
        pass
    return result


def check_dmarc_edv(domain, rua):
    """Check DMARC External Destination Verification for third-party report URIs."""
    if not rua:
        return {"checked": False, "issues": []}
    issues = []
    for uri in rua.split(","):
        uri = uri.strip()
        if not uri.startswith("mailto:"):
            continue
        addr = uri.replace("mailto:", "").split("!")[0]
        if "@" not in addr:
            continue
        dest_domain = addr.split("@")[1].lower()
        org_domain = domain.lower()
        if dest_domain == org_domain or dest_domain.endswith("." + org_domain):
            continue
        try:
            r = make_resolver()
            edv_name = f"{org_domain}._report._dmarc.{dest_domain}"
            answers = r.resolve(edv_name, "TXT")
            found = False
            for rdata in answers:
                if "v=DMARC1" in rdata.to_text().upper():
                    found = True
                    break
            if not found:
                issues.append(f"EDV record at {edv_name} missing v=DMARC1")
        except Exception:
            issues.append(f"No EDV record: {edv_name}")
    return {"checked": True, "issues": issues}


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


def check_dkim_strength(domain, selectors):
    """Check DKIM key type and strength for discovered selectors."""
    import base64
    results = {}
    r = make_resolver()
    for sel in selectors[:5]:
        info = {"type": "unknown", "bits": 0, "weak": False}
        try:
            answers = r.resolve(f"{sel}._domainkey.{domain}", "TXT")
            for rdata in answers:
                txt = rdata.to_text().strip('"').replace('" "', "")
                tags = {}
                for part in txt.split(";"):
                    part = part.strip()
                    if "=" in part:
                        k, v = part.split("=", 1)
                        tags[k.strip().lower()] = v.strip()
                key_type = tags.get("k", "rsa")
                info["type"] = key_type
                p_data = tags.get("p", "")
                if not p_data:
                    info["type"] = "revoked"
                    info["weak"] = False
                elif key_type == "ed25519":
                    info["bits"] = 256
                    info["weak"] = False
                elif key_type == "rsa":
                    try:
                        raw = base64.b64decode(p_data)
                        info["bits"] = len(raw) * 8
                        if info["bits"] <= 1024:
                            info["weak"] = True
                    except Exception:
                        info["bits"] = 0
                break
        except Exception:
            pass
        results[sel] = info
    return results


def check_dangling_dkim(domain, selectors):
    """Check for DKIM selectors that resolve via CNAME to NXDOMAIN (takeover risk)."""
    dangling = []
    r = make_resolver()
    for sel in selectors[:5]:
        try:
            answers = r.resolve(f"{sel}._domainkey.{domain}", "CNAME")
            cname_target = str(answers[0].target).rstrip(".")
            try:
                r.resolve(cname_target, "TXT")
            except dns.resolver.NXDOMAIN:
                dangling.append({"selector": sel, "cname": cname_target})
            except Exception:
                pass
        except Exception:
            pass
    return dangling


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

def walk_spf(domain, depth=0, visited=None, ip_count=None, includes=None):
    if visited is None:
        visited = set()
    if ip_count is None:
        ip_count = {"ip4": 0, "ip6": 0}
    if includes is None:
        includes = []
    if domain in visited or depth > 10:
        return 0, 0, depth, [], ip_count, includes
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
            return 0, void_lookups, depth, [], ip_count, includes

        for part in spf_txt.split():
            pl = part.lower()
            if pl.startswith("ip4:"):
                ip_count["ip4"] += 1
            elif pl.startswith("ip6:"):
                ip_count["ip6"] += 1
            elif pl.startswith("include:"):
                inc = pl.split(":", 1)[1]
                includes.append(inc)
                lookups += 1
                try:
                    sl, sv, sd, sdn, _, _ = walk_spf(inc, depth + 1, visited, ip_count, includes)
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
                    sl, sv, sd, sdn, _, _ = walk_spf(redir, depth + 1, visited, ip_count, includes)
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

    return lookups, void_lookups, max_depth, dangling, ip_count, includes


def analyze_spf_chain(domain):
    try:
        lookups, void_lookups, depth, dangling, ip_count, includes = walk_spf(domain)
        mt_includes = [i for i in includes if any(mt in i for mt in MULTI_TENANT_INCLUDES)]
        shared_infra_count = len(set(mt_includes))
        total_ips = ip_count["ip4"] + ip_count["ip6"]
        return {
            "spf_lookups": lookups,
            "spf_void_lookups": void_lookups,
            "spf_exceeds_limit": lookups > 10,
            "spf_void_exceeds": void_lookups > 2,
            "spf_dangling": dangling,
            "spf_chain_depth": depth,
            "spf_ip_count": total_ips,
            "spf_shared_includes": shared_infra_count,
            "spf_multi_tenant_list": list(set(mt_includes)),
            "spf_ip4_count": ip_count["ip4"],
            "spf_ip6_count": ip_count["ip6"],
        }
    except Exception:
        return {
            "spf_lookups": 0, "spf_void_lookups": 0,
            "spf_exceeds_limit": False, "spf_void_exceeds": False,
            "spf_dangling": [], "spf_chain_depth": 0,
            "spf_ip_count": 0, "spf_shared_includes": 0,
            "spf_multi_tenant_list": [],
            "spf_ip4_count": 0, "spf_ip6_count": 0,
        }


# ═══════════════════════════════════════════════════════════════
# Layer 5: Transport Security (MTA-STS, DANE)
# ═══════════════════════════════════════════════════════════════

def check_mta_sts(domain):
    result = {"present": False, "mode": "", "mx_patterns": [], "max_age": 0, "issues": []}
    try:
        r = make_resolver()
        answers = r.resolve(f"_mta-sts.{domain}", "TXT")
        for rdata in answers:
            if "v=STSv1" in rdata.to_text():
                result["present"] = True
                break
    except Exception:
        return result

    if not result["present"]:
        return result

    try:
        import urllib.request
        url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        req = urllib.request.Request(url, headers={"User-Agent": "SpoofScore/3.0"})
        resp = urllib.request.urlopen(req, timeout=10)
        body = resp.read().decode("utf-8", errors="replace")
        for line in body.splitlines():
            line = line.strip()
            if line.startswith("mode:"):
                result["mode"] = line.split(":", 1)[1].strip()
            elif line.startswith("mx:"):
                result["mx_patterns"].append(line.split(":", 1)[1].strip())
            elif line.startswith("max_age:"):
                try:
                    result["max_age"] = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
        if result["mode"] == "testing":
            result["issues"].append("MTA-STS in testing mode (not enforcing)")
        if result["mode"] == "none":
            result["issues"].append("MTA-STS mode=none (disabled)")
        if result["max_age"] and result["max_age"] < 86400:
            result["issues"].append(f"max_age={result['max_age']} (<24h, too short)")
    except Exception:
        result["issues"].append("Policy file unreachable")

    return result


def check_dane(mx_host):
    if not mx_host:
        return False
    try:
        r = make_resolver()
        answers = r.resolve(f"_25._tcp.{mx_host}", "TLSA")
        return len(answers) > 0
    except Exception:
        return False


def check_bimi(domain, dmarc_policy="missing"):
    result = {"present": False, "record": "", "logo_url": "", "vmc_url": "", "issues": []}
    try:
        r = make_resolver()
        answers = r.resolve(f"default._bimi.{domain}", "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"').replace('" "', "")
            if "v=BIMI1" in txt.upper():
                result["present"] = True
                result["record"] = txt
                tags = {}
                for part in txt.split(";"):
                    part = part.strip()
                    if "=" in part:
                        k, v = part.split("=", 1)
                        tags[k.strip().lower()] = v.strip()
                result["logo_url"] = tags.get("l", "")
                result["vmc_url"] = tags.get("a", "")
                break
    except Exception:
        return result

    if result["present"]:
        if dmarc_policy not in ("reject", "quarantine"):
            result["issues"].append("BIMI requires DMARC p=quarantine or p=reject")
        if not result["logo_url"]:
            result["issues"].append("No logo URL (l= tag empty)")
        elif not result["logo_url"].startswith("https://"):
            result["issues"].append("Logo URL must use HTTPS")
    return result


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

SECURITY_GATEWAY_PATTERNS = [
    "pphosted.com", "ppe-hosted.com",
    "mimecast.com", "mimecast-offshore.com",
    "barracudanetworks.com",
    "messagelabs.com", "symanteccloud.com",
    "iphmx.com",
    "fireeyecloud.com", "fireeye.com",
    "trendmicro.com", "in.trendmicro.eu",
    "forcepoint.com",
    "sophos.com",
    "ess.cisco.com",
    "exclaimer.net",
    "spamh.com",
]

def _is_security_gateway(mx_host):
    """Check if MX hostname belongs to a known email security gateway."""
    mx_lower = mx_host.lower()
    for pattern in SECURITY_GATEWAY_PATTERNS:
        if pattern in mx_lower:
            return True
    if mx_lower.endswith(".gov.sg") and "ict" in mx_lower:
        return True
    return False

def check_routing_risk(domain, mx_host):
    """Detect indirect MX routing to Exchange Online (Ghost-Sender risk).
    Only flags when MX points to a known security gateway AND an Exchange
    Online tenant endpoint is directly accessible behind it. Domains using
    Google, Amazon SES, or self-hosted mail are not affected."""
    result = {"indirect_mx": False, "eol_endpoint": "", "risk": "", "mx_target": ""}
    if not mx_host:
        return result

    mx_lower = mx_host.lower()

    if "protection.outlook.com" in mx_lower:
        return result

    if not _is_security_gateway(mx_host):
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


def check_echospoof_risk(domain, mx_host, spf_record):
    """Detect EchoSpoofing risk: Proofpoint in MX + SPF includes Proofpoint,
    allowing attackers to relay from their own M365 tenant through Proofpoint
    and pass SPF/DKIM/DMARC because Proofpoint's IPs are authorized."""
    result = {"risk": False, "detail": ""}
    if not mx_host or not spf_record:
        return result
    mx_lower = mx_host.lower()
    spf_lower = spf_record.lower()
    is_proofpoint_mx = any(p in mx_lower for p in ["pphosted.com", "ppe-hosted.com"])
    has_proofpoint_spf = "pphosted.com" in spf_lower or "ppe-hosted.com" in spf_lower
    if is_proofpoint_mx and has_proofpoint_spf:
        result["risk"] = True
        result["detail"] = (
            "MX and SPF both point to Proofpoint. An attacker can relay mail "
            "from their own M365 tenant through Proofpoint, passing SPF/DKIM/DMARC. "
            "Fix: restrict Proofpoint to accept only from known tenant IPs."
        )
    return result


def check_laundromarc(domain, dmarc_rua, platform):
    """LaunDroMARC advisory: M365 tenants relying on third-party DMARC
    processing may miss aggregate reports due to Microsoft's non-compliance
    with external report verification."""
    result = {"risk": False, "detail": ""}
    if platform != "Microsoft 365" or not dmarc_rua:
        return result
    for uri in dmarc_rua.split(","):
        uri = uri.strip()
        if not uri.startswith("mailto:"):
            continue
        addr = uri.replace("mailto:", "").split("!")[0]
        if "@" not in addr:
            continue
        dest = addr.split("@")[1].lower()
        if dest != domain.lower() and not dest.endswith("." + domain.lower()):
            result["risk"] = True
            result["detail"] = (
                f"rua={addr} is external to {domain}. M365 may not honour "
                f"EDV requirements, leading to missing DMARC aggregate reports."
            )
            break
    return result


def check_dnssec(domain):
    """Check if the domain has DNSSEC validation."""
    try:
        r = make_resolver()
        r.use_edns(0, dns.flags.DO, 4096)
        answers = r.resolve(domain, "A", raise_on_no_answer=False)
        if hasattr(answers.response, 'flags'):
            return bool(answers.response.flags & dns.flags.AD)
    except Exception:
        pass
    return False


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
    "pct_penalty": -5,
    "testing_mode_penalty": -10,
    "relaxed_alignment_penalty": -3,
    "spf_multiple_penalty": -5,
    "dmarc_multiple_penalty": -10,
    "weak_dkim_penalty": -5,
    "echospoof_penalty": -5,
    "spf_ptr_penalty": -2,
    "wide_cidr_penalty": -3,
}

def compute_score(result):
    score = 0
    penalties = {}

    effective = result["dmarc"].get("dmarc_effective_policy", result["dmarc"]["dmarc_policy"])
    score += SCORE_WEIGHTS["dmarc"].get(effective, 0)
    score += SCORE_WEIGHTS["spf"].get(result["spf"]["spf_mechanism"], 0)

    if result["spf"]["spf_mechanism"] == "permissive":
        p = SCORE_WEIGHTS["permissive_spf_penalty"]
        score += p
        penalties["spf_permissive"] = p

    if result["spf_chain"]["spf_exceeds_limit"]:
        p = SCORE_WEIGHTS["spf_exceed_penalty"]
        score += p
        penalties["spf_exceed"] = p

    if result["spf_chain"].get("spf_void_exceeds"):
        p = SCORE_WEIGHTS["spf_void_penalty"]
        score += p
        penalties["spf_void"] = p

    if result["dkim"]["dkim_found"]:
        score += SCORE_WEIGHTS["dkim"]

    tls_ver = result["smtp"]["tls_version"]
    for pattern, pts in SCORE_WEIGHTS["tls"].items():
        if pattern in tls_ver:
            score += pts
            break

    mta_sts = result["mta_sts"]
    if isinstance(mta_sts, dict):
        if mta_sts.get("present") and mta_sts.get("mode") == "enforce":
            score += SCORE_WEIGHTS["mta_sts"]
        elif mta_sts.get("present"):
            score += SCORE_WEIGHTS["mta_sts"] // 2
    elif mta_sts:
        score += SCORE_WEIGHTS["mta_sts"]

    if result["dane"]:
        score += SCORE_WEIGHTS["dane"]

    if result.get("rbl", {}).get("listed"):
        p = SCORE_WEIGHTS["rbl_penalty"]
        score += p
        penalties["rbl"] = p

    if result.get("sp_mismatch"):
        p = SCORE_WEIGHTS["sp_mismatch_penalty"]
        score += p
        penalties["sp_mismatch"] = p

    if result.get("routing_risk", {}).get("indirect_mx"):
        p = SCORE_WEIGHTS["routing_risk_penalty"]
        score += p
        penalties["routing_risk"] = p

    dmarc_t = result["dmarc"].get("dmarc_t", "")
    if dmarc_t == "y":
        p = SCORE_WEIGHTS["testing_mode_penalty"]
        score += p
        penalties["testing_mode"] = p

    pct = result["dmarc"].get("dmarc_pct", "")
    if pct and pct != "100":
        try:
            pct_val = int(pct)
            if pct_val < 100:
                p = SCORE_WEIGHTS["pct_penalty"]
                score += p
                penalties["pct"] = p
        except ValueError:
            pass

    aspf = result["dmarc"].get("dmarc_aspf", "r")
    adkim = result["dmarc"].get("dmarc_adkim", "r")
    if (aspf == "r" or adkim == "r") and result["dmarc"]["dmarc_policy"] != "missing":
        p = SCORE_WEIGHTS["relaxed_alignment_penalty"]
        score += p
        penalties["relaxed_alignment"] = p

    if result["spf"].get("spf_multiple"):
        p = SCORE_WEIGHTS["spf_multiple_penalty"]
        score += p
        penalties["spf_multiple"] = p

    if result["dmarc"].get("dmarc_multiple"):
        p = SCORE_WEIGHTS["dmarc_multiple_penalty"]
        score += p
        penalties["dmarc_multiple"] = p

    dkim_strength = result.get("dkim_strength", {})
    if any(info.get("weak") for info in dkim_strength.values()):
        p = SCORE_WEIGHTS["weak_dkim_penalty"]
        score += p
        penalties["weak_dkim"] = p

    if result.get("echospoof", {}).get("risk"):
        p = SCORE_WEIGHTS["echospoof_penalty"]
        score += p
        penalties["echospoof"] = p

    if result["spf"].get("spf_has_ptr"):
        p = SCORE_WEIGHTS["spf_ptr_penalty"]
        score += p
        penalties["spf_ptr"] = p

    if result["spf"].get("spf_wide_cidrs"):
        p = SCORE_WEIGHTS["wide_cidr_penalty"]
        score += p
        penalties["wide_cidr"] = p

    score = max(0, min(100, score))

    if score >= 80:   grade = "A"
    elif score >= 60: grade = "B"
    elif score >= 40: grade = "C"
    elif score >= 20: grade = "D"
    else:             grade = "F"

    return score, grade, penalties


# ═══════════════════════════════════════════════════════════════
# Full Domain Scan
# ═══════════════════════════════════════════════════════════════

def scan_domain(domain, json_mode=False):
    domain = domain.strip().lower().rstrip(".")
    result = {"domain": domain}
    t0 = time.time()
    total = 12

    show_progress(domain, 0, total_steps=total, json_mode=json_mode)
    result["mx"] = check_mx(domain)
    result["spf"] = check_spf(domain)
    result["dmarc"] = check_dmarc(domain)

    show_progress(domain, 1, total_steps=total, json_mode=json_mode)
    mx_host = result["mx"]["mx_primary"]
    result["platform"] = fingerprint_platform(mx_host, domain)

    show_progress(domain, 2, total_steps=total, json_mode=json_mode)
    result["dkim"] = check_dkim(domain, result["platform"])

    show_progress(domain, 3, total_steps=total, json_mode=json_mode)
    result["dkim_strength"] = check_dkim_strength(domain, result["dkim"]["dkim_selectors"])
    result["dkim_dangling"] = check_dangling_dkim(domain, result["dkim"]["dkim_selectors"])

    show_progress(domain, 4, total_steps=total, json_mode=json_mode)
    result["smtp"] = probe_smtp(mx_host)

    show_progress(domain, 5, total_steps=total, json_mode=json_mode)
    result["spf_chain"] = analyze_spf_chain(domain)

    show_progress(domain, 6, total_steps=total, json_mode=json_mode)
    result["mta_sts"] = check_mta_sts(domain)
    result["dane"] = check_dane(mx_host)
    result["bimi"] = check_bimi(domain, result["dmarc"]["dmarc_policy"])
    result["tls_rpt"] = check_tls_rpt(domain)

    show_progress(domain, 7, total_steps=total, json_mode=json_mode)
    result["rbl"] = check_rbl(mx_host)
    result["fcrdns"] = check_fcrdns(mx_host)

    show_progress(domain, 8, total_steps=total, json_mode=json_mode)
    dmarc_sp = result["dmarc"].get("dmarc_sp", "")
    dmarc_p = result["dmarc"]["dmarc_policy"]
    result["sp_mismatch"] = (
        dmarc_p in ("reject", "quarantine") and dmarc_sp == "none"
    )

    show_progress(domain, 9, total_steps=total, json_mode=json_mode)
    result["routing_risk"] = check_routing_risk(domain, mx_host)
    result["echospoof"] = check_echospoof_risk(
        domain, mx_host, result["spf"]["spf_record"]
    )
    result["laundromarc"] = check_laundromarc(
        domain, result["dmarc"]["dmarc_rua"], result["platform"]
    )

    show_progress(domain, 10, total_steps=total, json_mode=json_mode)
    result["dmarc_edv"] = check_dmarc_edv(domain, result["dmarc"]["dmarc_rua"])
    result["dnssec"] = check_dnssec(domain)

    show_progress(domain, 11, total_steps=total, json_mode=json_mode)
    score, grade, penalties = compute_score(result)
    result["score"] = score
    result["grade"] = grade
    result["penalties"] = penalties

    effective = result["dmarc"].get("dmarc_effective_policy", result["dmarc"]["dmarc_policy"])
    result["spoofable"] = effective in ("none", "missing")

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

    echo = result.get("echospoof", {})
    if echo.get("risk"):
        fixes.append({
            "priority": "CRITICAL",
            "issue": "EchoSpoofing risk: Proofpoint accepts relay from any M365 tenant.",
            "fix": "Configure Proofpoint to only accept mail from your known M365 tenant IPs. Enable IP-based filtering on inbound connectors.",
            "record": "",
        })

    if result["spf"].get("spf_multiple"):
        fixes.append({
            "priority": "CRITICAL",
            "issue": "Multiple SPF records found. RFC 7208 §4.5: domain MUST NOT have more than one SPF record. Both are invalidated.",
            "fix": f"Merge all SPF records into a single TXT record at {domain}.",
            "record": "",
        })

    if result["dmarc"].get("dmarc_multiple"):
        fixes.append({
            "priority": "CRITICAL",
            "issue": "Multiple DMARC records found. RFC 7489 §6.6.3: domain MUST NOT have more than one DMARC record. Both are ignored.",
            "fix": f"Remove duplicate DMARC records at _dmarc.{domain}.",
            "record": "",
        })

    if result["dmarc"].get("dmarc_t") == "y":
        fixes.append({
            "priority": "HIGH",
            "issue": f"DMARC t=y (testing mode). Receivers MAY treat p={result['dmarc']['dmarc_policy']} as p=none.",
            "fix": f"Remove t=y from _dmarc.{domain} to enforce the policy.",
            "record": "",
        })

    pct = result["dmarc"].get("dmarc_pct", "")
    if pct and pct != "100" and result["dmarc"]["dmarc_policy"] != "missing":
        fixes.append({
            "priority": "HIGH",
            "issue": f"DMARC pct={pct}. Only {pct}% of failing messages are subject to the policy. The rest are treated as p=none.",
            "fix": f"Set pct=100 or remove pct tag in _dmarc.{domain}.",
            "record": "",
        })

    aspf = result["dmarc"].get("dmarc_aspf", "r")
    adkim = result["dmarc"].get("dmarc_adkim", "r")
    if result["dmarc"]["dmarc_policy"] in ("reject", "quarantine"):
        if aspf == "r" and adkim == "r":
            fixes.append({
                "priority": "MEDIUM",
                "issue": "Both SPF and DKIM alignment are relaxed. Cousin-domain attacks can pass DMARC.",
                "fix": f"Set aspf=s; adkim=s in _dmarc.{domain} for strict alignment.",
                "record": "",
            })

    if result["spf"].get("spf_has_ptr"):
        fixes.append({
            "priority": "MEDIUM",
            "issue": "SPF record uses 'ptr' mechanism, deprecated by RFC 7208 §5.5 due to performance and reliability concerns.",
            "fix": "Replace ptr with explicit ip4:/ip6: ranges or include: mechanisms.",
            "record": "",
        })

    wide = result["spf"].get("spf_wide_cidrs", [])
    if wide:
        fixes.append({
            "priority": "HIGH",
            "issue": f"SPF authorizes overly broad CIDR(s): {', '.join(wide[:3])}. Shared IP space enables BreakSPF attacks.",
            "fix": "Narrow ip4: ranges to only your mail servers, or use include: to delegate to your provider.",
            "record": "",
        })

    dkim_str = result.get("dkim_strength", {})
    for sel, info in dkim_str.items():
        if info.get("weak"):
            fixes.append({
                "priority": "HIGH",
                "issue": f"DKIM selector '{sel}' uses {info['type'].upper()} {info['bits']}-bit key. Keys ≤1024-bit are factorizable.",
                "fix": f"Rotate to 2048-bit RSA or Ed25519 key for {sel}._domainkey.{domain}.",
                "record": "",
            })

    dkim_dang = result.get("dkim_dangling", [])
    for d in dkim_dang:
        fixes.append({
            "priority": "CRITICAL",
            "issue": f"DKIM selector '{d['selector']}' has CNAME to {d['cname']} which is NXDOMAIN. Attacker can register it and sign as your domain.",
            "fix": f"Remove the CNAME record at {d['selector']}._domainkey.{domain} or re-register {d['cname']}.",
            "record": "",
        })

    edv = result.get("dmarc_edv", {})
    if edv.get("issues"):
        for iss in edv["issues"]:
            fixes.append({
                "priority": "MEDIUM",
                "issue": f"DMARC reporting: {iss}",
                "fix": "Add an EDV authorization record at the destination domain to receive aggregate reports.",
                "record": f"v=DMARC1 (as TXT record at <org-domain>._report._dmarc.<dest-domain>)",
            })

    laundro = result.get("laundromarc", {})
    if laundro.get("risk"):
        fixes.append({
            "priority": "MEDIUM",
            "issue": f"LaunDroMARC: {laundro['detail']}",
            "fix": "Consider using a rua address at your own domain, or verify report delivery independently.",
            "record": "",
        })

    mta_sts = result.get("mta_sts", {})
    if isinstance(mta_sts, dict) and mta_sts.get("present") and mta_sts.get("mode") == "testing":
        fixes.append({
            "priority": "MEDIUM",
            "issue": "MTA-STS is in testing mode. Mail transport encryption is not enforced.",
            "fix": f"Update mta-sts.{domain}/.well-known/mta-sts.txt to mode: enforce",
            "record": "",
        })

    bimi = result.get("bimi", {})
    if bimi.get("present") and bimi.get("issues"):
        for iss in bimi["issues"]:
            fixes.append({
                "priority": "MEDIUM",
                "issue": f"BIMI: {iss}",
                "fix": "Ensure DMARC is at p=quarantine or p=reject and BIMI logo uses HTTPS.",
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
{CY}  .-')     _ (`-.                                       {R}
{CY} ( OO ).  ( (OO  )                                      {R}
{CY}(_)---\\_)_.`     \\ .-'),-----.  .-'),-----.    ,------. {R}
{CY}/    _ |(__...--''( OO'  .-.  '( OO'  .-.  '('-| _.---' {R}
{CY}\\  :` `. |  /  | |/   |  | |  |/   |  | |  |(OO|(_\\     {R}
{CY} '..`''.)|  |_.' |\\_) |  |\\|  |\\_) |  |\\|  |/  |  '--.  {R}
{CY}.-._)   \\|  .___.'  \\ |  | |  |  \\ |  | |  |\\_)|  .--'  {R}
{CY}\\       /|  |        `'  '-'  '   `'  '-'  '  \\|  |_)   {R}
{CY} `-----' `--'          `-----'      `-----'    `--'     {R}
{CY}  .-')                           _  .-')     ('-.       {R}
{CY} ( OO ).                        ( \\( -O )  _(  OO)      {R}
{CY}(_)---\\_)   .-----.  .-'),-----. ,------. (,------.     {R}
{CY}/    _ |   '  .--./ ( OO'  .-.  '|   /`. ' |  .---'     {R}
{CY}\\  :` `.   |  |('-. /   |  | |  ||  /  | | |  |         {R}
{CY} '..`''.) /_) |OO  )\\_) |  |\\|  ||  |_.' |(|  '--.      {R}
{CY}.-._)   \\ ||  |`-'|   \\ |  | |  ||  .  '.' |  .--'      {R}
{CY}\\       /(_'  '--'\\    `'  '-'  '|  |\\  \\  |  `---.     {R}
{CY} `-----'    `-----'      `-----' `--' '--' `------'     {R}

{B}   SpoofScore{R} {DM}v{__version__}{R}
{DM}   Can someone impersonate your domain via email?{R}
{DM}   made by {B}bau1u{R} {DM}— github.com/harrizuan/spoofscore{R}
"""

LAYER_NAMES = [
    ("🔐", "DNS Auth"),
    ("📧", "Platform"),
    ("🔑", "DKIM"),
    ("🔑", "Key Strength"),
    ("🔒", "SMTP/TLS"),
    ("🔗", "SPF Chain"),
    ("🛡️ ", "Transport"),
    ("📡", "Reputation"),
    ("⚙️ ", "Policy"),
    ("🔀", "Routing"),
    ("🔍", "Validation"),
    ("📊", "Scoring"),
]

def show_progress(domain, step, total_steps=9, json_mode=False):
    if json_mode:
        return
    icon, name = LAYER_NAMES[step] if step < len(LAYER_NAMES) else ("⚙️ ", "Scoring")
    pct = round((step + 1) / total_steps * 100)
    filled = round((step + 1) / total_steps * 20)
    bar = f"{CY}{'█' * filled}{'░' * (20 - filled)}{R}"
    line = f"   {bar} {icon}  {DM}{name:<12}{R} {DM}{pct:>3}%{R}"
    print(f"\033[2K\r{line}", end="", flush=True)

def clear_progress():
    print(f"\033[2K\r", end="", flush=True)

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
    print(f"\n   {icon}  {B}{WH}{title}{R}")
    print(f"   {DM}{'─'*52}{R}")

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

    if r["spoofable"]:
        verdict_bg, verdict_icon, verdict_text = BG_RD, "⚠", "SPOOFABLE"
    else:
        verdict_bg, verdict_icon, verdict_text = BG_GR, "✓", "PROTECTED"

    print(f"\n   {CY}{'━' * 56}{R}")
    print(f"   {B}{WH}{r['domain']}{R}{time_str}")
    print()
    print(f"      {score_bar(score, 24)}  {gc}{B}{score}{R}{DM}/100{R}  {gc}{B}{grade}{R}")
    print()
    print(f"      {verdict_bg}{WH}{B} {verdict_icon} {verdict_text} {R}")
    print(f"   {CY}{'━' * 56}{R}")

    # Layer 1: DNS Authentication
    section("🔐", "DNS Authentication")
    row("MX Record", tag(r["mx"]["has_mx"]),
        r["mx"]["mx_primary"] or "no MX")
    if r["spf"].get("spf_multiple"):
        row("SPF", f"{RD}{B}MULTIPLE RECORDS{R}", "RFC 7208 violation")
    else:
        row("SPF", fmt_spf(r["spf"]["spf_mechanism"]))
    if r["spf"]["spf_record"]:
        rec = r["spf"]["spf_record"]
        print(f"      {DM}{'':>16} {rec[:60]}{'...' if len(rec)>60 else ''}{R}")
    if r["spf"].get("spf_has_ptr"):
        print(f"      {YL}{'':>16} ⚠ SPF uses ptr mechanism (deprecated RFC 7208 §5.5){R}")
    if r["spf"].get("spf_syntax_errors"):
        for err in r["spf"]["spf_syntax_errors"]:
            print(f"      {RD}{'':>16} ⚠ Syntax: {err}{R}")

    if r["dmarc"].get("dmarc_multiple"):
        row("DMARC", f"{RD}{B}MULTIPLE RECORDS{R}", "RFC 7489 violation — record ignored")
    else:
        row("DMARC", fmt_policy(r["dmarc"]["dmarc_policy"]))

    effective = r["dmarc"].get("dmarc_effective_policy", "")
    if effective and effective != r["dmarc"]["dmarc_policy"]:
        row("Effective", fmt_policy(effective),
            "after t=y" if r["dmarc"].get("dmarc_t") == "y" else f"pct={r['dmarc'].get('dmarc_pct','')}")

    if r["dmarc"]["dmarc_rua"]:
        row("Reporting", f"{DM}{r['dmarc']['dmarc_rua'][:55]}{R}")

    aspf = r["dmarc"].get("dmarc_aspf", "r")
    adkim = r["dmarc"].get("dmarc_adkim", "r")
    if r["dmarc"]["dmarc_policy"] != "missing":
        aspf_str = f"{GR}strict{R}" if aspf == "s" else f"{YL}relaxed{R}"
        adkim_str = f"{GR}strict{R}" if adkim == "s" else f"{YL}relaxed{R}"
        row("Alignment", f"SPF={aspf_str}  DKIM={adkim_str}")

    if r["dmarc"].get("dmarc_t") == "y":
        row("Testing Mode", f"{RD}{B}t=y{R}", "receivers MAY downgrade policy")

    if r["dmarc"].get("dmarc_pct") and r["dmarc"]["dmarc_pct"] != "100":
        row("Coverage", f"{YL}{B}pct={r['dmarc']['dmarc_pct']}{R}",
            "not fully enforced" if r["dmarc"]["dmarc_policy"] != "none" else "")

    np = r["dmarc"].get("dmarc_np", "")
    if np:
        row("NP Policy", fmt_policy(np), "non-existent subdomains")

    sp = r["dmarc"].get("dmarc_sp", "")
    if sp:
        row("SP Policy", fmt_policy(sp), "subdomains")

    deprecated = r["dmarc"].get("dmarc_deprecated_tags", [])
    if deprecated:
        dep_list = ", ".join(deprecated)
        print(f"      {YL}{'':>16} ⚠ Deprecated tag(s): {dep_list} (DMARCbis RFC 9989){R}")

    dkim_sels = r["dkim"]["dkim_selectors"]
    row("DKIM", tag(r["dkim"]["dkim_found"]),
        f"selectors: {', '.join(dkim_sels)}" if dkim_sels else "none found")
    if r["dkim"].get("dkim_wildcard"):
        print(f"      {YL}{'':>16} ⚠ Wildcard _domainkey detected (catch-all){R}")

    dkim_str = r.get("dkim_strength", {})
    if dkim_str:
        for sel, info in dkim_str.items():
            if info.get("type") == "revoked":
                row(f"  {sel}", f"{DM}revoked{R}", "key removed")
            elif info.get("weak"):
                row(f"  {sel}", f"{RD}{B}{info['type'].upper()} {info['bits']}bit{R}", "WEAK — upgrade to 2048+")
            elif info.get("bits"):
                ktype = info["type"].upper()
                bits = info["bits"]
                c = GR if (ktype == "ED25519" or bits >= 2048) else YL
                row(f"  {sel}", f"{c}{ktype} {bits}bit{R}")

    dkim_dang = r.get("dkim_dangling", [])
    if dkim_dang:
        for d in dkim_dang:
            print(f"      {RD}  ⚠ DKIM {d['selector']}: CNAME → {d['cname']} (NXDOMAIN — takeover risk){R}")

    # Layer 2: SMTP/TLS
    section("🔒", "SMTP/TLS Probing")
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
    section("📧", "Mail Platform")
    plat = r["platform"]
    plat_icons = {
        "Google Workspace": "Google", "Microsoft 365": "Microsoft",
        "Amazon SES": "AWS SES", "ProtonMail": "Proton",
    }
    row("Provider", f"{B}{plat_icons.get(plat, plat)}{R}")

    # Layer 4: SPF Chain
    section("🔗", "SPF Chain Analysis")
    lookups = ch["spf_lookups"]
    lookup_color = GR if lookups <= 7 else YL if lookups <= 10 else RD
    row("DNS Lookups", f"{lookup_color}{B}{lookups}{R}{DM}/10{R}",
        f"{RD}EXCEEDS RFC 7208{R}" if ch["spf_exceeds_limit"] else "")
    void_c = ch.get("spf_void_lookups", 0)
    void_color = GR if void_c <= 1 else YL if void_c <= 2 else RD
    row("Void Lookups", f"{void_color}{B}{void_c}{R}{DM}/2{R}",
        f"{RD}EXCEEDS §4.6.4{R}" if ch.get("spf_void_exceeds") else "")
    row("Chain Depth", f"{ch['spf_chain_depth']}")
    ip_count = ch.get("spf_ip_count", 0)
    if ip_count:
        ip_color = GR if ip_count <= 20 else YL if ip_count <= 50 else RD
        row("IP Ranges", f"{ip_color}{B}{ip_count}{R}",
            f"v4:{ch.get('spf_ip4_count',0)} v6:{ch.get('spf_ip6_count',0)}")
    shared = ch.get("spf_shared_includes", 0)
    if shared:
        shared_color = YL if shared <= 3 else RD
        row("Shared Infra", f"{shared_color}{B}{shared}{R} multi-tenant include(s)")
        for mt in ch.get("spf_multi_tenant_list", [])[:5]:
            print(f"      {YL}{'':>16} ↳ {mt}{R}")
    wide = r["spf"].get("spf_wide_cidrs", [])
    if wide:
        for cidr in wide[:3]:
            print(f"      {RD}  ⚠ Wide CIDR: {B}{cidr}{R} {DM}(BreakSPF risk — shared IP space){R}")
    if ch["spf_dangling"]:
        for dang in ch["spf_dangling"]:
            print(f"      {RD}  ⚠ Dangling: {B}{dang}{R} {DM}(NXDOMAIN — takeover risk){R}")

    # Layer 5: Transport & Reputation
    section("🛡️ ", "Transport & Reputation")
    mta_sts = r["mta_sts"]
    if isinstance(mta_sts, dict):
        if mta_sts.get("present"):
            mode = mta_sts.get("mode", "")
            if mode == "enforce":
                row("MTA-STS", f"{GR}{B}enforce{R}", "RFC 8461")
            elif mode == "testing":
                row("MTA-STS", f"{YL}{B}testing{R}", "not enforcing")
            elif mode == "none":
                row("MTA-STS", f"{RD}{B}none{R}", "disabled")
            else:
                row("MTA-STS", tag(True), "RFC 8461")
            for iss in mta_sts.get("issues", []):
                print(f"      {YL}{'':>16} ⚠ {iss}{R}")
        else:
            row("MTA-STS", tag(False), "RFC 8461")
    else:
        row("MTA-STS", tag(mta_sts), "RFC 8461")

    row("DANE/TLSA", tag(r["dane"]), "RFC 7672")
    row("DNSSEC", tag(r.get("dnssec", False)), "domain-level")

    bimi = r["bimi"]
    row("BIMI", tag(bimi["present"]))
    if bimi.get("present"):
        if bimi.get("vmc_url"):
            row("  VMC", f"{GR}present{R}")
        else:
            row("  VMC", f"{YL}missing{R}", "no Verified Mark Certificate")
        for iss in bimi.get("issues", []):
            print(f"      {YL}{'':>16} ⚠ {iss}{R}")
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

    edv = r.get("dmarc_edv", {})
    if edv.get("issues"):
        for iss in edv["issues"]:
            print(f"      {YL}  ⚠ {iss}{R}")

    laundro = r.get("laundromarc", {})
    if laundro.get("risk"):
        print(f"      {YL}  ⚠ LaunDroMARC: {laundro['detail']}{R}")

    # Routing Risk
    rr = r.get("routing_risk", {})
    echo = r.get("echospoof", {})
    if rr.get("indirect_mx") or echo.get("risk"):
        section("🔀", "Routing & Supply Chain Risk")
        if rr.get("indirect_mx"):
            row("Ghost-Sender", f"{RD}{B}VULNERABLE{R}")
            row("MX Target", f"{rr['mx_target']}")
            row("EOL Endpoint", f"{RD}{rr['eol_endpoint']}{R}", "directly accessible")
            print(f"      {RD}  ⚠ Exchange Online tenant accepts direct connections.{R}")
            print(f"      {RD}    Spoofed mail can bypass security gateway entirely.{R}")
        if echo.get("risk"):
            row("EchoSpoofing", f"{RD}{B}AT RISK{R}")
            print(f"      {RD}  ⚠ {echo['detail'][:80]}{R}")
    elif r.get("platform") == "Microsoft 365":
        section("🔀", "Routing Risk")
        row("Routing", f"{GR}{B}DIRECT{R}", "MX points to Exchange Online")

    # Score Breakdown
    section("📊", "Score Breakdown")
    effective_p = r["dmarc"].get("dmarc_effective_policy", r["dmarc"]["dmarc_policy"])
    dmarc_pts = w["dmarc"].get(effective_p, 0)
    spf_pts = w["spf"].get(r["spf"]["spf_mechanism"], 0)
    dkim_pts = w["dkim"] if r["dkim"]["dkim_found"] else 0
    tls_pts = 0
    for pat, pts in w["tls"].items():
        if pat in r["smtp"]["tls_version"]:
            tls_pts = pts
            break
    mta_sts_d = r["mta_sts"]
    if isinstance(mta_sts_d, dict):
        if mta_sts_d.get("present") and mta_sts_d.get("mode") == "enforce":
            mta_pts = w["mta_sts"]
        elif mta_sts_d.get("present"):
            mta_pts = w["mta_sts"] // 2
        else:
            mta_pts = 0
    else:
        mta_pts = w["mta_sts"] if mta_sts_d else 0
    dane_pts = w["dane"] if r["dane"] else 0

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

    score_row("DMARC", dmarc_pts, 30, f"p={effective_p}")
    score_row("SPF", spf_pts, 20, r["spf"]["spf_mechanism"])
    score_row("DKIM", dkim_pts, 15)
    score_row("TLS", tls_pts, 15, r["smtp"]["tls_version"] or "none")
    score_row("MTA-STS", mta_pts, 10)
    score_row("DANE/TLSA", dane_pts, 10)

    penalties = r.get("penalties", {})
    for key, val in penalties.items():
        labels = {
            "spf_exceed": (">10 lookups", "SPF lookups"),
            "spf_void": (">2 void", "SPF void"),
            "spf_permissive": ("+all", "SPF +all"),
            "rbl": ("blocklisted", "RBL"),
            "sp_mismatch": ("subdomain gap", "sp= mismatch"),
            "routing_risk": ("Ghost-Sender", "Routing"),
            "testing_mode": ("t=y testing", "DMARC t=y"),
            "pct": ("partial", "DMARC pct"),
            "relaxed_alignment": ("relaxed", "Alignment"),
            "spf_multiple": ("multiple SPF", "SPF dup"),
            "dmarc_multiple": ("multiple DMARC", "DMARC dup"),
            "weak_dkim": ("≤1024bit", "DKIM weak"),
            "echospoof": ("relay risk", "EchoSpoof"),
            "spf_ptr": ("deprecated", "SPF ptr"),
            "wide_cidr": ("broad range", "Wide CIDR"),
        }
        note, label = labels.get(key, (key, key))
        penalty_row(label, val, note)

    print(f"      {CY}{'─' * 44}{R}")
    print(f"      {B}{'TOTAL':<14}{R} {score_bar(score)}  {gc}{B}{score}/100  {grade}{R}")

    print()

    # Remediation
    if r.get("remediation"):
        section("🔧", "Remediation")
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
    mta_sts = r.get("mta_sts", {})
    if isinstance(mta_sts, dict):
        mta_present = "Yes" if mta_sts.get("present") else "No"
        mta_mode = mta_sts.get("mode", "")
    else:
        mta_present = "Yes" if mta_sts else "No"
        mta_mode = ""

    dkim_str = r.get("dkim_strength", {})
    weak_sels = [s for s, i in dkim_str.items() if i.get("weak")]
    key_info = "; ".join(f"{s}:{i.get('type','?')}/{i.get('bits',0)}" for s, i in dkim_str.items())

    return {
        "domain": r["domain"],
        "score": r["score"],
        "grade": r["grade"],
        "spoofable": "Yes" if r["spoofable"] else "No",
        "has_mx": "Yes" if r["mx"]["has_mx"] else "No",
        "mx_primary": r["mx"]["mx_primary"] or "",
        "spf_mechanism": r["spf"]["spf_mechanism"],
        "spf_record": r["spf"]["spf_record"],
        "spf_multiple": "Yes" if r["spf"].get("spf_multiple") else "No",
        "spf_has_ptr": "Yes" if r["spf"].get("spf_has_ptr") else "No",
        "spf_wide_cidrs": "; ".join(r["spf"].get("spf_wide_cidrs", [])),
        "spf_multi_tenant": "; ".join(r["spf"].get("spf_multi_tenant_includes", [])),
        "dmarc_policy": r["dmarc"]["dmarc_policy"],
        "dmarc_effective": r["dmarc"].get("dmarc_effective_policy", ""),
        "dmarc_record": r["dmarc"]["dmarc_record"],
        "dmarc_rua": r["dmarc"]["dmarc_rua"],
        "dmarc_aspf": r["dmarc"].get("dmarc_aspf", "r"),
        "dmarc_adkim": r["dmarc"].get("dmarc_adkim", "r"),
        "dmarc_pct": r["dmarc"].get("dmarc_pct", ""),
        "dmarc_np": r["dmarc"].get("dmarc_np", ""),
        "dmarc_t": r["dmarc"].get("dmarc_t", ""),
        "dmarc_multiple": "Yes" if r["dmarc"].get("dmarc_multiple") else "No",
        "dkim_found": "Yes" if r["dkim"]["dkim_found"] else "No",
        "dkim_selectors": "; ".join(r["dkim"]["dkim_selectors"]),
        "dkim_key_info": key_info,
        "dkim_weak": "; ".join(weak_sels),
        "dkim_dangling": "; ".join(d["selector"] for d in r.get("dkim_dangling", [])),
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
        "spf_ip_count": r["spf_chain"].get("spf_ip_count", 0),
        "spf_shared_includes": r["spf_chain"].get("spf_shared_includes", 0),
        "mta_sts": mta_present,
        "mta_sts_mode": mta_mode,
        "dane_tlsa": "Yes" if r["dane"] else "No",
        "dnssec": "Yes" if r.get("dnssec") else "No",
        "bimi": "Yes" if r["bimi"]["present"] else "No",
        "bimi_vmc": "Yes" if r["bimi"].get("vmc_url") else "No",
        "tls_rpt": "Yes" if r["tls_rpt"]["present"] else "No",
        "rbl_listed": "; ".join(r.get("rbl", {}).get("listed", [])),
        "rbl_clean": "Yes" if not r.get("rbl", {}).get("listed") and r.get("rbl", {}).get("checked") else "No",
        "fcrdns_ptr": r.get("fcrdns", {}).get("ptr", ""),
        "fcrdns_verified": "Yes" if r.get("fcrdns", {}).get("verified") else "No",
        "sp_mismatch": "Yes" if r.get("sp_mismatch") else "No",
        "dkim_wildcard": "Yes" if r.get("dkim", {}).get("dkim_wildcard") else "No",
        "routing_risk": "Yes" if r.get("routing_risk", {}).get("indirect_mx") else "No",
        "routing_eol_endpoint": r.get("routing_risk", {}).get("eol_endpoint", ""),
        "echospoof_risk": "Yes" if r.get("echospoof", {}).get("risk") else "No",
        "laundromarc_risk": "Yes" if r.get("laundromarc", {}).get("risk") else "No",
        "edv_issues": "; ".join(r.get("dmarc_edv", {}).get("issues", [])),
    }


# ═══════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        prog="spoofscore",
        description="Multi-layer email security scanner. 11 analysis layers, interaction-aware scoring (0-100).",
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
