# sploitmap

An **attack-surface mapper**, nxc-style. Not a `nmap | searchsploit` wrapper — it
actively fingerprints services, correlates them against a curated knowledge base
of exploits, CVEs, default creds and techniques, and hands you the exact commands.
**Finds and recommends; never exploits.** Exam-legal by default.

```bash
sploitmap 10.10.10.5                  # scan, fingerprint, map (exam-safe)
sploitmap 10.10.10.5 --cve            # + nmap vuln,vulners NSE (catches MS17-010 etc.)
sploitmap x --xml scan.xml            # ingest an existing nmap -oX
sploitmap targets.txt                 # file of hosts/CIDRs
sploitmap 10.10.10.5 --nuclei         # LABS ONLY — nuclei web scan (see note)
```

## What it does — 4 stages

1. **DISCOVER** — `nmap -sV` (top 1000, or `--full` for all ports).
2. **FINGERPRINT** — actively probes every web service (title, `Server`/`X-Powered-By`
   headers, body signatures) to recover the **real product + version nmap misses** —
   e.g. *Apache Tomcat 9.0.16* hiding under a *ManageEngine AppManager* front end.
   Matches a curated **product knowledge base**.
3. **CORRELATE** — for each service:
   - **ExploitDB** via searchsploit, **relevance-ranked** — exact-version matches
     (`✓ver`) float to the top, DoS is demoted, so the `→` recommendation is never
     the hot-but-wrong-product exploit.
   - **Product KB** — notable CVEs (Ghostcat, Drupalgeddon, BlueKeep…), **default
     credentials**, and product-specific attack tips. Catches what searchsploit's
     text-match misses (searchsploit can't find Ghostcat for Tomcat 9.0.16 — the KB can).
   - **Service KB** — per-protocol techniques with ready commands (SMB null-session &
     MS17-010, FTP anon, MSSQL `xp_cmdshell`, HTTP content discovery, …), pointed at
     `nxc` where relevant. Maps SMB/MSSQL/RDP by port+alias, not just name.
   - **nmap CVEs** from `--cve` NSE output.
4. **RECOMMEND** — rich per-service output + an **ATTACK SURFACE — start here (ranked)**
   summary that scores every service (hot exploits, default creds, products, CVEs) so
   you know which door to try first. Pre-filled exploit-db + NVD research links.

## Flags

| flag | effect |
|---|---|
| `--cve` | nmap `vuln,vulners` NSE (version/CPE→CVE **and** protocol checks like EternalBlue) |
| `--full` | all 65535 ports |
| `--no-fp` | skip active web fingerprinting (offline / stealth) |
| `--loose` | searchsploit product-only (noisier; default is version-pinned) |
| `--nuclei` / `--deep` | **LABS ONLY** — nuclei (fast / full `-as` auto-scan) |
| `--xml FILE` | ingest an existing `nmap -oX` instead of scanning |
| `-w N` | parallel workers (default 8) · `--no-color` |

## ⚠️ OSCP exam note
**Default `sploitmap`, `--cve` and `--no-fp` are exam-legal** — active fingerprinting,
nmap NSE, searchsploit and a static knowledge base. It only *suggests* commands; you
type and run every exploit yourself, which is allowed.

**`--nuclei` is LABS ONLY.** nuclei is an automated vulnerability scanner that also
*exploits* (many templates trigger the bug to confirm it) — so it falls under the exam's
banned "automated vulnerability scanner" **and** "automated exploitation tool" categories.
It is **off by default** and prints a LAB-MODE warning. Never run it against exam machines.
(Verify restrictions against your current OSCP exam guide.)

## Install
```bash
ln -sf "$PWD/sploitmap.py" ~/.local/bin/sploitmap
```
Requires: `nmap`, `searchsploit` (core); `nuclei` (only for `--nuclei`).
