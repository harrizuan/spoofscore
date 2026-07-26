<p align="center">
  <img src="https://img.shields.io/badge/🛡️_SpoofScore-v3.0.0-blue?style=for-the-badge&labelColor=0d1117" alt="SpoofScore v3.0.0" />
</p>

<h1 align="center">SpoofScore</h1>

<p align="center">
  <b>Can someone impersonate your domain via email?</b><br>
  <sub>11-layer email security scanner with interaction-aware scoring, spoofability verdict, and copy-paste remediation.</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-3776AB?logo=python&logoColor=white" alt="Python 3.8+" />
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License" />
  <img src="https://img.shields.io/badge/dependencies-1_(dnspython)-brightgreen" alt="Dependencies: 1" />
  <img src="https://img.shields.io/badge/layers-11-blueviolet" alt="11 Layers" />
  <img src="https://img.shields.io/badge/DKIM_selectors-80+-orange" alt="80+ DKIM Selectors" />
  <img src="https://img.shields.io/badge/RBL_zones-40-red" alt="40 RBL Zones" />
</p>

<p align="center">
  <sub>Made by <b><a href="https://www.tfsec.org">bau1u</a></b></sub><br><br>
  <a href="https://www.tfsec.org"><img src="https://img.shields.io/badge/tfsec.org-000?style=flat-square&logo=firefox&logoColor=white" alt="Website" /></a>
  <a href="https://www.linkedin.com/in/harrizuan/"><img src="https://img.shields.io/badge/LinkedIn-0A66C2?style=flat-square&logo=linkedin&logoColor=white" alt="LinkedIn" /></a>
  <a href="https://hackerone.com/bau1u"><img src="https://img.shields.io/badge/HackerOne-494649?style=flat-square&logo=hackerone&logoColor=white" alt="HackerOne" /></a>
  <a href="https://x.com/bau1u"><img src="https://img.shields.io/badge/@bau1u-000?style=flat-square&logo=x&logoColor=white" alt="X" /></a>
  <a href="https://github.com/harrizuan"><img src="https://img.shields.io/badge/GitHub-181717?style=flat-square&logo=github&logoColor=white" alt="GitHub" /></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#what-it-checks">11 Layers</a> •
  <a href="#scoring-model">Scoring</a> •
  <a href="#how-it-differs">vs Competitors</a> •
  <a href="#usage">Usage</a>
</p>

---

Most email security tools ask: *"Is your DNS configured correctly?"*

SpoofScore asks a different question:

> **"Can an attacker send email as you, right now?"**

One command. Eleven layers. A clear answer: **SPOOFABLE** or **PROTECTED**.

---

## Demo

<p align="center">
  <img src="demo.png" alt="SpoofScore v3.0.0 scanning google.com" width="700" />
</p>

---

## Quick Start

```bash
pip install dnspython
python spoofscore.py example.com
```

That's it. One dependency. No config files. No API keys.

---

## What It Checks

| # | Layer | What | How |
|---|-------|------|-----|
| 1 | **DNS Authentication** | MX, SPF, DMARC, DKIM | Provider-aware DKIM with 80+ selectors + wildcard canary |
| 2 | **SMTP/TLS Probing** | STARTTLS, TLS version, cipher | Live connection to mail server on port 25 |
| 3 | **Mail Platform** | Email service provider | Fingerprint from MX hostname (Google, M365, SES, Zoho, ProtonMail, Mimecast) |
| 4 | **DKIM Key Strength** | Key type, bit length, revocation | RSA vs Ed25519, flags weak keys (<=1024-bit), detects revoked selectors |
| 5 | **SPF Chain Analysis** | Include tree walking, BreakSPF | RFC 7208 10-lookup limit, void lookups, dangling includes, multi-tenant shared infra, wide CIDR detection |
| 6 | **Transport Security** | MTA-STS, DANE/TLSA, BIMI, TLS-RPT, DNSSEC | Policy file validation, certificate checks (RFC 8461, RFC 7672) |
| 7 | **Reputation** | RBL/DNSBL scan | 40 major blocklist zones (Spamhaus, SpamCop, Barracuda, SORBS, UCEPROTECT, and more) |
| 8 | **Infrastructure** | FCrDNS, DMARC sp=, alignment | Forward-confirmed reverse DNS, subdomain policy mismatch, aspf/adkim analysis |
| 9 | **Policy Analysis** | pct, t=y, np=, deprecated tags | Detects DMARC testing mode, partial enforcement, and DMARCbis deprecated tags |
| 10 | **Supply-Chain Risk** | Ghost-Sender, EchoSpoofing | Gateway bypass via direct tenant delivery, Proofpoint relay abuse |
| 11 | **Composite Score** | Weighted 0-100, interaction penalties | Spoofability verdict + prioritized remediation with exact DNS records |

---

## Scoring Model

<table>
<tr>
<td>

**Positive Signals**

| Component | Points |
|-----------|-------:|
| DMARC `p=reject` | **+30** |
| DMARC `p=quarantine` | +15 |
| DMARC `p=none` | +5 |
| SPF `-all` (hardfail) | **+20** |
| SPF `~all` (softfail) | +15 |
| DKIM present | +15 |
| TLS 1.3 | +15 |
| TLS 1.2 | +10 |
| MTA-STS | +10 |
| DANE/TLSA | +10 |

</td>
<td>

**Penalties**

| Issue | Points |
|-------|-------:|
| SPF `+all` (permissive) | **-10** |
| RBL blocklisted | **-10** |
| SPF exceeds 10-lookup limit | -5 |
| DMARC `sp=` mismatch | -5 |
| Ghost-Sender routing risk | **-5** |
| EchoSpoofing risk | **-5** |
| DMARC `pct` < 100 | -5 |
| DMARC `t=y` testing mode | -5 |
| Relaxed SPF+DKIM alignment | -3 |
| Multiple SPF records | -3 |
| Multiple DMARC records | -3 |
| Weak DKIM key (<=1024-bit) | -3 |
| SPF `ptr` mechanism | -2 |
| SPF wide CIDR (<=\/20) | -2 |
| SPF void lookups > 2 | -3 |

**Grades**

| Grade | Score |
|:-----:|------:|
| **A** | 80-100 |
| **B** | 60-79 |
| **C** | 40-59 |
| **D** | 20-39 |
| **F** | 0-19 |

</td>
</tr>
</table>

---

## What Makes SpoofScore Different

> [!IMPORTANT]
> SpoofScore is not just another DMARC checker. Most tools validate DNS records.
> SpoofScore tells you if those records actually **prevent spoofing**, and what to fix if they don't.

### Feature by feature vs the competition

| Capability | SpoofScore | Spoofy | espoofer | checkdmarc | mailvalidator | dnsarmor |
|:-----------|:----------:|:------:|:--------:|:----------:|:-------------:|:--------:|
| **Primary question** | Spoofable? | Spoofable? | Bypass auth? | Valid record? | Security grade? | DNS secure? |
| Composite 0-100 score | ✅ | ❌ | ❌ | ❌ | Penalty | Finding |
| 11-layer analysis | ✅ | ❌ | ❌ | ❌ | Partial | DNS only |
| Spoofability verdict | ✅ | ✅ | N/A | ❌ | ❌ | ❌ |
| Wildcard DKIM canary | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Provider-aware DKIM | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| DKIM key strength audit | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| DKIM selectors | **80+** | API | N/A | 0 | 0 | Built-in |
| BreakSPF detection | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| SPF multi-tenant analysis | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| SPF dangling includes | ✅ | ❌ | ❌ | ❌ | Void only | ❌ |
| SPF void lookup limit | ✅ | ❌ | ❌ | ✅ | ✅ | ❌ |
| DMARC `sp=` mismatch | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| DMARC alignment analysis | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| DMARC pct/t=y/np= parsing | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Ghost-Sender detection | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| EchoSpoofing detection | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| RBL/DNSBL zones | **40** | 0 | 0 | 0 | 104 | 13 |
| FCrDNS | ✅ | ❌ | ❌ | ✅ | Partial | ❌ |
| MTA-STS policy validation | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ |
| DANE/TLSA + DNSSEC | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ |
| BIMI + TLS-RPT | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ |
| Remediation w/ DNS records | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Interaction-aware scoring | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Batch CSV for research | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ |
| Dependencies | **1** | 2 | 5+ | 7 | 6+ | 3 |

> [!NOTE]
> **Where others beat us (for now):**
> `mailvalidator` checks 104 RBL zones (we check 40), and `dnsarmor` does DNSSEC chain validation.
> We focus on the question that matters most to red teams and defenders: **can this domain be spoofed?**

---

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

### Export to CSV (for research/batch analysis)

```bash
python spoofscore.py -f domains.txt -o results.csv
```

### JSON output (includes remediation)

```bash
python spoofscore.py example.com --json
```

### Custom thread count for large batches

```bash
python spoofscore.py -f 1000-domains.txt -o scan.csv --smtp-threads 30
```

<details>
<summary><b>All CLI options</b></summary>

| Flag | Description | Default |
|------|-------------|---------|
| `domains` | One or more domains to scan | |
| `-f`, `--file` | File with one domain per line | |
| `-o`, `--output` | Output CSV file path | |
| `--json` | Output JSON instead of CLI report | `false` |
| `--smtp-threads` | SMTP probing threads for batch mode | `10` |
| `--version` | Print version and exit | |

</details>

---

## Output Formats

<details>
<summary><b>CSV columns (for research/batch scanning)</b></summary>

| Column | Description |
|--------|-------------|
| `domain` | Target domain |
| `score` | Composite score 0-100 |
| `grade` | Letter grade A-F |
| `spoofable` | Yes/No verdict |
| `has_mx` | MX record exists |
| `mx_primary` | Primary MX hostname |
| `spf_mechanism` | SPF all-mechanism (hardfail/softfail/neutral/permissive/missing) |
| `spf_record` | Raw SPF TXT record |
| `spf_multiple` | Multiple SPF records detected |
| `spf_has_ptr` | SPF uses deprecated `ptr` mechanism |
| `spf_wide_cidrs` | Wide CIDR ranges (<=\/20) in SPF |
| `dmarc_policy` | DMARC p= value |
| `dmarc_record` | Raw DMARC TXT record |
| `dmarc_effective` | Effective DMARC policy (after pct/t=y) |
| `dmarc_aspf` | SPF alignment mode (strict/relaxed) |
| `dmarc_adkim` | DKIM alignment mode (strict/relaxed) |
| `dmarc_rua` | DMARC aggregate report URI |
| `dkim_found` | DKIM selector discovered |
| `dkim_selectors` | Found selector names |
| `dkim_key_info` | Key type and bit length |
| `dkim_weak` | Weak key detected (<=1024-bit) |
| `dkim_dangling` | Dangling DKIM CNAME (subdomain takeover risk) |
| `starttls` | STARTTLS support |
| `tls_version` | Negotiated TLS version |
| `tls_cipher` | Cipher suite |
| `platform` | Detected mail platform |
| `spf_lookups` | SPF DNS lookup count |
| `spf_void_lookups` | SPF void lookup count |
| `spf_exceeds_limit` | Exceeds 10-lookup limit |
| `spf_void_exceeds` | Exceeds void lookup limit |
| `spf_dangling` | NXDOMAIN includes |
| `spf_chain_depth` | Include tree depth |
| `spf_ip_count` | Total IP ranges in SPF tree |
| `spf_shared_includes` | Multi-tenant includes found |
| `spf_multi_tenant_list` | List of shared SPF includes |
| `mta_sts` | MTA-STS configured |
| `mta_sts_mode` | MTA-STS policy mode (enforce/testing/none) |
| `dane_tlsa` | DANE/TLSA present |
| `dnssec` | DNSSEC validation (AD flag) |
| `bimi` | BIMI record present |
| `tls_rpt` | TLS-RPT configured |
| `rbl_listed` | Blocklisted zones |
| `rbl_clean` | Clean on all RBL zones |
| `fcrdns_ptr` | PTR record |
| `fcrdns_verified` | Forward-confirmed |
| `sp_mismatch` | sp= policy mismatch |
| `dkim_wildcard` | Wildcard _domainkey detected |
| `routing_risk` | Ghost-Sender routing risk |
| `routing_eol_endpoint` | Direct Exchange Online endpoint |
| `echospoof_risk` | EchoSpoofing relay risk |
| `laundromarc_risk` | LaunDroMARC report risk |

</details>

<details>
<summary><b>JSON output (single domain)</b></summary>

```json
{
  "domain": "example.com",
  "score": 45,
  "grade": "C",
  "spoofable": "Yes",
  "has_mx": "Yes",
  "mx_primary": "mx1.example.com",
  "spf_mechanism": "softfail",
  "dmarc_policy": "none",
  "dmarc_effective": "none",
  "dmarc_aspf": "relaxed",
  "dmarc_adkim": "relaxed",
  "dkim_found": "Yes",
  "dkim_selectors": ["selector1"],
  "dkim_key_info": "RSA 2048-bit",
  "platform": "Microsoft 365",
  "mta_sts": "No",
  "mta_sts_mode": "none",
  "dane_tlsa": "No",
  "dnssec": "No",
  "rbl_clean": "Yes",
  "routing_risk": "No",
  "echospoof_risk": "No",
  "remediation": [
    {
      "priority": "CRITICAL",
      "issue": "DMARC policy is 'none' (monitor only)",
      "fix": "Upgrade to p=reject to block spoofed mail",
      "record": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
    }
  ]
}
```

</details>

---

## Research

SpoofScore was built for and validated in academic research. We scanned **900 government domains** across 10 ASEAN nations and 4 comparative countries as part of a study presented at IDSECCONF 2026.

Key findings from the scan:
- **367 out of 900** government domains (40.8%) are spoofable
- Average email security score: **37.9/100** (Grade D)
- **Zero** domains achieved Grade A
- **97** domains vulnerable to Ghost-Sender gateway bypass
- **520** domains share multi-tenant SPF infrastructure (BreakSPF exposure)

If you use SpoofScore in your research, please cite us:

```bibtex
@software{spoofscore,
  author = {Ahmad Al Harrizuan Bin Izadin},
  title = {SpoofScore: 11-Layer Email Security Scanner},
  version = {3.0.0},
  url = {https://github.com/harrizuan/spoofscore},
  year = {2026}
}
```

---

## Notes

> [!TIP]
> Run SpoofScore from a **VPS with port 25 open** for full Layer 2 (SMTP/TLS) results.
> Most ISPs and cloud providers block outbound port 25 on home connections.

- Python 3.8+ required. Only one dependency: `dnspython`
- DKIM probes 80+ selectors covering all major providers. Custom selectors may still be missed
- RBL checks query 40 major blocklist zones. Some zones may rate-limit
- Layer 10 checks for Ghost-Sender and EchoSpoofing supply-chain risks
- This is a point-in-time scan. DNS records and mail server configs change

```bash
pip install dnspython
```

---

## License

[MIT](LICENSE). Use it, fork it, build on it.

---

<p align="center">
  <sub>Built by <a href="https://www.tfsec.org">bau1u</a>. One dependency. Eleven layers. One answer.</sub><br>
  <b>Can someone impersonate your domain?</b><br>
  <sub>Find out in seconds.</sub>
</p>
