# sploitmap v3.0

A reconnaissance, **vulnerability-intelligence** and manual-exploitation
*recommendation* framework for OSCP-style engagements. It takes an imperfect
service fingerprint, identifies the real software, discovers **applicable real
CVEs** from live intelligence sources, finds relevant public exploits, and
recommends accurate manual investigation steps — **without producing misleading
results, and without ever launching an exploit itself.**

The point is not "nmap piped into searchsploit". The point is the
**applicability engine**: for every CVE, it checks the detected version against
the real affected-version ranges in NVD and labels each finding
`CONFIRMED / PROBABLE / POSSIBLE`, with evidence. A 2007 Ragnarok bug that lists
Apache as an unbounded wildcard does **not** get reported against your
Apache 2.4.49.

```bash
sploitmap 10.10.10.5                     # scan + map (exam profile, default)
sploitmap 10.10.10.5 --cve               # + nmap vuln/vulners NSE
sploitmap 10.10.10.5 --deep-enum         # + credentialed enum suggestions
sploitmap --xml scan.xml                 # ingest an existing nmap -oX
sploitmap 10.10.10.5 --profile lab       # enable lab-only engines (nuclei, nikto)
sploitmap 10.10.10.5 --format html -o report.html
sploitmap cve CVE-2021-41773             # look up one CVE (full detail)
sploitmap research "Apache httpd 2.4.49" # ad-hoc product research
sploitmap update-db                      # refresh CISA KEV feed + caches
sploitmap doctor                         # dependencies / connectivity / policy
```

## How it works (4 stages)

1. **DISCOVER** — `nmap -sV` (or ingest `--xml`). NSE CVE strings are harvested.
2. **FINGERPRINT** — actively probes web services (HTTP headers, title, body
   signatures, TLS cert CN) to recover the product+version nmap misses, e.g.
   *Apache Tomcat 9.0.16* behind a *ManageEngine* console. Conflicting signals
   are preserved, not silently overwritten.
3. **CORRELATE** — the intelligence engine:
   - resolves product → **CPE** (curated alias map + NVD CPE dictionary),
   - pulls CVEs from **NVD 2.0**, then **re-verifies each against the detected
     version** (semantic version comparison, affected ranges, wildcard
     detection) to assign a confidence + evidence,
   - enriches with **FIRST EPSS** (exploit probability), **CISA KEV** (actively
     exploited), and **Exploit-DB / PoC references** (searchsploit + NVD
     exploit-tagged refs).
4. **RECOMMEND** — per finding: prerequisites (parsed from the CVSS vector),
   research commands (all *inspect/copy*, never a fabricated run line), a manual
   test process, and a validation step that warns about distro backports.
   Plus an **ATTACK SURFACE — start here (ranked)** summary scored on real
   evidence (KEV, exploit existence, EPSS, CVSS) — not description keywords.

## Intelligence sources

| Source | Use | Online | Offline |
|---|---|---|---|
| NIST **NVD 2.0** | CVEs, CPE match, CVSS, CWE, refs | API (cached) | from cache |
| FIRST **EPSS** | exploitation probability | API (cached) | from cache |
| CISA **KEV** | actively-exploited flag | feed + NVD inline | `update-db` feed |
| **Exploit-DB** | public exploits / PoCs | local `searchsploit` | local |
| **nmap NSE** | version-less protocol bugs (MS17-010) | `--cve` | n/a |

Everything is cached under `~/.local/share/sploitmap/`. `--offline` serves only
cached intel. **Privacy:** queries carry only public product ids / CVE ids — the
target IP and your identity never leave the box. Set `NVD_API_KEY` to lift the
anonymous 5-req/30s rate limit to 50.

## Exam vs lab

Two profiles, declared in [smap/policies/policy.yaml](smap/policies/policy.yaml)
and enforced positively (a capability runs only if the active profile lists it).

- **EXAM (default)** — enumeration + external research only; you run every
  exploit by hand. `nuclei`, `nikto`, credential spraying and any auto-exploit
  are **blocked**. `--cve` (nmap vuln NSE) is *permitted but flagged* as
  intrusive — confirm it is exam-legal for you.
- **LAB (`--profile lab`)** — adds automated scanners against explicitly
  authorized targets. Even here, sploitmap **never launches an exploit itself.**

> The policy is based on PEN-200 / OSCP guidance. **Verify against the current
> official OffSec exam guide** — the manifest is deliberately conservative where
> eligibility is uncertain.

## Install

```bash
# option A: just run it (keeps ~/.local/bin/sploitmap on PATH)
ln -sf "$PWD/sploitmap.py" ~/.local/bin/sploitmap

# option B: packaged install
pipx install .        # or: pip install --user .
```

Requires Python ≥3.10 and `nmap` + `searchsploit`. Optional tools (nxc, whatweb,
nuclei, …) are used when present and never fatal if missing — run
`sploitmap doctor` to see what's available.

## Architecture

```
smap/
  core/          versioning, cpe, models, cache, http
  discovery/     nmap run + XML ingest
  fingerprint/   active HTTP/TLS probing + product signatures
  intelligence/  nvd, epss, cisa, exploitdb, engine
  correlation/   applicability (the confidence engine)
  recommendations/
  protocols/     per-service enumeration knowledge (nxc-pointed)
  policies/      exam/lab manifest + enforcement
  reporting/     terminal (rich), json, markdown, html
tests/           64 tests inc. real NVD fixtures for false-positive resistance
```

## Tests

```bash
python3 -m pytest tests/ -q      # 64 tests
```

Covers version ordering, **applicability against frozen real NVD records**
(exact match → CONFIRMED, patched version → NOT_APPLICABLE, wildcard FP →
dropped, ranges → PROBABLE), CPE resolution, XML ingest, exam/lab isolation,
serialize round-trip, report generation, and the CLI (offline).

## Limitations / honesty

- Confidence is **evidence about applicability, not proof of exploitability** —
  a CONFIRMED version match can still be a backported-patched distro build. The
  tool says so and tells you how to verify.
- CPE resolution covers the common OSCP products out of the box (alias map) and
  falls back to NVD's CPE dictionary; an exotic product may resolve weakly or
  not at all (then you get research links, not false CVEs).
- EPSS/KEV/NVD require network on first lookup; after that, cache + `--offline`.
- It **finds and recommends**. It does not exploit. By design.
