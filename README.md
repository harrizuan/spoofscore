<p align="center">
  <img src="https://img.shields.io/badge/🛡️_SpoofScore-v2.1.0-blue?style=for-the-badge&labelColor=0d1117" alt="SpoofScore v2.1.0" />
</p>

<h1 align="center">SpoofScore</h1>

<p align="center">
  <b>Can someone impersonate your domain via email?</b><br>
  <sub>9 layer email security scanner with scoring, spoofability verdict, and copy paste remediation.</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-3776AB?logo=python&logoColor=white" alt="Python 3.8+" />
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License" />
  <img src="https://img.shields.io/badge/dependencies-1_(dnspython)-brightgreen" alt="Dependencies: 1" />
  <img src="https://img.shields.io/badge/layers-9-blueviolet" alt="9 Layers" />
  <img src="https://img.shields.io/badge/DKIM_selectors-80+-orange" alt="80+ DKIM Selectors" />
  <img src="https://img.shields.io/badge/RBL_zones-10-red" alt="10 RBL Zones" />
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
  <a href="#what-it-checks">9 Layers</a> •
  <a href="#scoring-model">Scoring</a> •
  <a href="#how-it-differs">vs Competitors</a> •
  <a href="#usage">Usage</a>
</p>

---

Most email security tools ask: *"Is your DNS configured correctly?"*

SpoofScore asks a different question:

> **"Can an attacker send email as you, right now?"**

One command. Nine layers. A clear answer: **SPOOFABLE** or **PROTECTED**.

---

## Demo

```
$ python spoofscore.py google.com

  .-')     _ (`-.                                        .-')                           _  .-')     ('-.
 ( OO ).  ( (OO  )                                      ( OO ).                        ( \( -O )  _(  OO)
(_)---\_)_.`     \ .-'),-----.  .-'),-----.    ,------.(_)---\_)   .-----.  .-'),-----. ,------. (,------.
/    _ |(__...--''( OO'  .-.  '( OO'  .-.  '('-| _.---'/    _ |   '  .--./ ( OO'  .-.  '|   /`. ' |  .---'
\  :` `. |  /  | |/   |  | |  |/   |  | |  |(OO|(_\    \  :` `.   |  |('-. /   |  | |  ||  /  | | |  |
 '..`''.)|  |_.' |\_) |  |\|  |\_) |  |\|  |/  |  '--.  '..`''.) /_) |OO  )\_) |  |\|  ||  |_.' |(|  '--.
.-._)   \|  .___.'  \ |  | |  |  \ |  | |  |\_)|  .--' .-._)   \ ||  |`-'|   \ |  | |  ||  .  '.' |  .--'
\       /|  |        `'  '-'  '   `'  '-'  '  \|  |_)  \       /(_'  '--'\    `'  '-'  '|  |\  \  |  `---.
 `-----' `--'          `-----'      `-----'    `--'     `-----'    `-----'      `-----' `--' '--' `------'

   SpoofScore v2.1.0    Can someone impersonate your domain via email?
   made by bau1u — github.com/harrizuan/spoofscore

   Scanning 1 domain...

   [1/1] google.com
   ████████████████ 📡  Reputation

   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   google.com  (12.4s)

      Score    ██████████████░░░░░░  70/100
      Grade    ▌▌▌ B ▐▐▐
      Verdict  ✓ PROTECTED
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

   ┌────────────────────────────────────────────────────┐
   │ 🔐  Layer 1 — DNS Authentication                  │
   └────────────────────────────────────────────────────┘
      MX Record        ✓  smtp.google.com
      SPF              ~all (softfail)
                       v=spf1 include:_spf.google.com ~all
      DMARC            reject
      Reporting        mailto:mailauth-reports@google.com
      DKIM             ✓  selectors: 20230601, 20221208

   ┌────────────────────────────────────────────────────┐
   │ 🔒  Layer 2 — SMTP/TLS Probing                    │
   └────────────────────────────────────────────────────┘
      STARTTLS         Yes
      TLS Version      TLSv1.3
      Cipher           TLS_AES_256_GCM_SHA384

   ┌────────────────────────────────────────────────────┐
   │ 📧  Layer 3 — Mail Platform                       │
   └────────────────────────────────────────────────────┘
      Provider         Google

   ┌────────────────────────────────────────────────────┐
   │ 🔗  Layer 4 — SPF Chain Analysis                   │
   └────────────────────────────────────────────────────┘
      DNS Lookups      1/10
      Void Lookups     0/2
      Chain Depth      1

   ┌────────────────────────────────────────────────────┐
   │ 🛡️  Layer 5 — Transport & Reputation               │
   └────────────────────────────────────────────────────┘
      MTA-STS          ✓  RFC 8461
      DANE/TLSA        ✗  RFC 7672
      BIMI             ✗
      TLS-RPT          ✗
      FCrDNS           Verified  sd-in-f27.1e100.net
      RBL Status       Clean  10 zones scanned

   ┌────────────────────────────────────────────────────┐
   │ 🔀  Layer 9 — Routing Risk Analysis               │
   └────────────────────────────────────────────────────┘
      Routing          ✓  DIRECT  MX points to Exchange Online

   ┌────────────────────────────────────────────────────┐
   │ 📊  Layer 6 — Score Breakdown                      │
   └────────────────────────────────────────────────────┘
      DMARC          ██████████ +30/30  p=reject
      SPF            ████████░░ +15/20  softfail
      DKIM           ██████████ +15/15
      TLS            ░░░░░░░░░░  +0/15  none
      MTA-STS        ██████████ +10/10
      DANE/TLSA      ░░░░░░░░░░  +0/10
      ────────────────────────────────────────────
      TOTAL          ██████████████░░░░░░  70/100  B

   ✓  PROTECTED — DMARC enforcement blocks email spoofing

   Completed in 12.4s
```

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
| 4 | **SPF Chain Analysis** | Include tree walking | RFC 7208 10-lookup limit, void lookup limit, dangling include detection |
| 5 | **Transport Security** | MTA-STS, DANE/TLSA, BIMI, TLS-RPT | Checks all transport protocols (RFC 8461, RFC 7672) |
| 6 | **Reputation** | RBL/DNSBL scan | 10 major blocklist zones (Spamhaus, SpamCop, Barracuda, SORBS, UCEPROTECT) |
| 7 | **Infrastructure** | FCrDNS, DMARC sp= | Forward-confirmed reverse DNS + subdomain policy mismatch |
| 8 | **Composite Score** | Weighted 0-100 | Spoofability verdict + remediation with exact DNS records to copy paste |
| 9 | **Routing Risk** | Ghost-Sender detection | Indirect MX to Exchange Online: gateway bypass via direct tenant delivery |

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
| Routing risk (Ghost-Sender) | **-5** |
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
| 9-layer analysis | ✅ | ❌ | ❌ | ❌ | Partial | DNS only |
| Spoofability verdict | ✅ | ✅ | N/A | ❌ | ❌ | ❌ |
| Wildcard DKIM canary | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Provider-aware DKIM | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| DKIM selectors | **80+** | API | N/A | 0 | 0 | Built-in |
| SPF dangling includes | ✅ | ❌ | ❌ | ❌ | Void only | ❌ |
| SPF void lookup limit | ✅ | ❌ | ❌ | ✅ | ✅ | ❌ |
| DMARC `sp=` mismatch | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| RBL/DNSBL zones | **10** | 0 | 0 | 0 | 104 | 13 |
| FCrDNS | ✅ | ❌ | ❌ | ✅ | Partial | ❌ |
| MTA-STS + DANE | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ |
| BIMI + TLS-RPT | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ |
| Remediation w/ DNS records | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Ghost-Sender detection | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Batch CSV for research | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ |
| Dependencies | **1** | 2 | 5+ | 7 | 6+ | 3 |

> [!NOTE]
> **Where others beat us (for now):**
> `mailvalidator` checks 104 RBL zones (we check 10), and `dnsarmor` does DNSSEC chain validation.
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
| `dmarc_policy` | DMARC p= value |
| `dmarc_record` | Raw DMARC TXT record |
| `dmarc_rua` | DMARC aggregate report URI |
| `dkim_found` | DKIM selector discovered |
| `dkim_selectors` | Found selector names |
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
| `mta_sts` | MTA-STS configured |
| `dane_tlsa` | DANE/TLSA present |
| `bimi` | BIMI record present |
| `tls_rpt` | TLS-RPT configured |
| `rbl_listed` | Blocklisted zones |
| `rbl_clean` | Clean on all RBL zones |
| `fcrdns_ptr` | PTR record |
| `fcrdns_verified` | Forward-confirmed |
| `sp_mismatch` | sp= policy mismatch |
| `dkim_wildcard` | Wildcard _domainkey detected |
| `routing_risk` | Ghost-Sender routing risk detected |
| `routing_eol_endpoint` | Direct Exchange Online endpoint |

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
  "dkim_found": "Yes",
  "dkim_selectors": ["selector1"],
  "platform": "Microsoft 365",
  "mta_sts": "No",
  "dane_tlsa": "No",
  "rbl_clean": "Yes",
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

## Notes

> [!TIP]
> Run SpoofScore from a **VPS with port 25 open** for full Layer 2 (SMTP/TLS) results.
> Most ISPs and cloud providers block outbound port 25 on home connections.

- Python 3.8+ required. Only one dependency: `dnspython`
- DKIM probes 80+ selectors. Custom selectors may still be missed
- RBL checks query 10 major blocklist zones. Some zones may rate limit
- Layer 9 checks for Ghost-Sender routing risk (indirect MX to Exchange Online)
- This is a point in time scan. DNS records and mail server configs change

```bash
pip install dnspython
```

---

## License

[MIT](LICENSE). Use it, fork it, build on it.

---

<p align="center">
  <sub>Built by <a href="https://www.tfsec.org">bau1u</a>. One dependency. Nine layers. One answer.</sub><br>
  <b>Can someone impersonate your domain?</b><br>
  <sub>Find out in seconds.</sub>
</p>
