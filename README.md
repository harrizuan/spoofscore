# SpoofScore — Multi-Layer Email Security Scanner

A spoofability-focused email security assessment tool that scans any domain across 8 assessment layers and produces a composite score (0-100), letter grade, explicit spoofability verdict, and actionable remediation with exact DNS records to publish.

Unlike configuration auditors that tell sysadmins "is your email set up correctly?", SpoofScore answers the security question: **"Can someone impersonate this domain via email?"**

Built for the IDSECCONF 2026 research paper:
*"99% Spoofable: Measuring Government Email Authentication Failures across 12 Countries with Live Spoofing Proof"*

## What It Checks

| Layer | What | Details |
|-------|------|---------|
| 1. DNS Authentication | MX, SPF, DMARC, DKIM | Provider-aware DKIM with 80+ selectors, wildcard canary to prevent false positives |
| 2. SMTP/TLS Probing | STARTTLS, TLS version, cipher suite, banner | Active connection to mail server on port 25 |
| 3. Mail Platform | Fingerprint from MX hostname | Google Workspace, Microsoft 365, Amazon SES, Zoho, ProtonMail, Mimecast, self-hosted |
| 4. SPF Chain Analysis | Recursive include walking | RFC 7208 10-lookup limit, void lookup limit (2), dangling include detection |
| 5. Transport Security | MTA-STS, DANE/TLSA, BIMI, TLS-RPT | Full transport layer coverage |
| 6. Reputation | RBL/DNSBL blocklist scan (10 zones) | Spamhaus, SpamCop, Barracuda, SORBS, UCEPROTECT, etc. |
| 7. Infrastructure | FCrDNS, DMARC sp= analysis | Forward-confirmed reverse DNS, subdomain policy mismatch detection |
| 8. Composite Score | Weighted 0-100 with A/B/C/D/F | Spoofability verdict + prioritized remediation with exact DNS records |

### Scoring Model

| Component | Points |
|-----------|--------|
| DMARC p=reject | +30 |
| DMARC p=quarantine | +15 |
| DMARC p=none | +5 |
| SPF -all (hardfail) | +20 |
| SPF ~all (softfail) | +15 |
| DKIM present | +15 |
| TLS 1.3 | +15 |
| TLS 1.2 | +10 |
| MTA-STS | +10 |
| DANE/TLSA | +10 |
| SPF +all (permissive) | -10 |
| SPF exceeds 10-lookup limit | -5 |
| SPF void lookups >2 | -3 |
| RBL blocklisted | -10 |
| DMARC sp= mismatch | -5 |

Grades: **A** (80+), **B** (60-79), **C** (40-59), **D** (20-39), **F** (<20)

### Key Features

- **Spoofability verdict** — Clear binary: SPOOFABLE or PROTECTED
- **Wildcard DKIM canary** — Random selector probe to prevent false positives from catch-all `_domainkey` DNS
- **Provider-aware DKIM** — Detects platform from MX, prioritizes known selectors (Google, M365, SES, Zoho, ProtonMail, Mimecast)
- **SPF void lookup counting** — RFC 7208 §4.6.4 void lookup limit (max 2), not just the 10-lookup limit
- **Dangling SPF include detection** — Flags NXDOMAIN includes as subdomain takeover risks
- **RBL blocklist scanning** — 10 major DNSBL zones (Spamhaus, SpamCop, Barracuda, SORBS, UCEPROTECT, etc.)
- **FCrDNS** — Forward-confirmed reverse DNS verification for MX server IPs
- **DMARC sp= mismatch** — Warns when sp=none weakens subdomain protection despite enforcing p=reject
- **Remediation with exact DNS records** — Copy-paste ready records + provider-specific DKIM instructions
- **Batch research mode** — CSV export designed for national-scale scanning with country grouping

## Install

```bash
pip install dnspython
```

No other dependencies. Python 3.8+.

## Usage

### Scan a single domain

```bash
python spoofscore.py example.com
```

### Scan multiple domains

```bash
python spoofscore.py example.com another.org third.gov
```

### Scan from a file

```bash
python spoofscore.py -f domains.txt
```

### Export to CSV

```bash
python spoofscore.py -f domains.txt -o results.csv
```

### JSON output (with remediation included)

```bash
python spoofscore.py example.com --json
```

## How It Differs from Other Tools

| Feature | SpoofScore | Spoofy | checkdmarc | mailvalidator | dnsarmor | espoofer |
|---------|-----------|--------|------------|---------------|----------|----------|
| **Primary question** | "Can someone spoof this domain?" | "Is it spoofable?" | "Is the record valid?" | "What's the security grade?" | "Is DNS secure?" | "Can we bypass auth?" |
| Composite score (0-100) | **Yes** | No | No | Penalty model | Finding-based | No |
| 8-layer analysis | **Yes** | No | No | Partial | DNS-focused | SMTP-focused |
| Spoofability verdict | **Yes** | **Yes** | No | No | No | N/A (active) |
| SPF dangling include | **Yes** | No | No | Void count | No | No |
| Wildcard DKIM canary | **Yes** | No | No | No | No | No |
| Provider-aware DKIM | **Yes** | No | No | No | No | No |
| DKIM selectors | **80+** | API-based | 0 | 0 | Built-in | N/A |
| RBL/blocklist zones | **10** | 0 | 0 | 104 | 13 | 0 |
| FCrDNS | **Yes** | No | **Yes** | Partial | No | No |
| DMARC sp= mismatch | **Yes** | No | No | No | No | No |
| Remediation w/ DNS records | **Yes** | No | No | **Yes** | **Yes** | No |
| Batch CSV for research | **Yes** | **Yes** | **Yes** | No | **Yes** | No |
| Dependencies | 1 (dnspython) | 2 | 7 | 6+ | 3 | 5+ |
| Language | Python | Python | Python | Python | Python | Python |

## Notes

- **Port 25 access required** for SMTP/TLS probing. Run from a VPS for full results.
- DKIM probes 80+ selectors with provider-aware prioritization. Custom selectors may still be missed.
- RBL checks query 10 major blocklist zones. Some zones may rate-limit queries.
- This is a point-in-time scan. DNS records and mail server configs can change.

## License

MIT

## Author

**bau1u** (Amirul Azuan Harrizuan Izadin)

## Citation

If you use this tool in research, please cite:

```
Izadin, A. A. H. (2026). "99% Spoofable: Measuring Government Email Authentication
Failures across 12 Countries with Live Spoofing Proof." IDSECCONF 2026.
```
