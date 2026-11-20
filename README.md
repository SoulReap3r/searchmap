# sploitmap

`nmap -sV` → per-service **exploit/CVE mapping**, nxc-style. Finds exploits; never runs them.

```bash
sploitmap 10.10.10.5                  # scan + map (exam-safe)
sploitmap 10.10.10.5 --cve            # + nmap vuln,vulners scripts (catches MS17-010 etc.)
sploitmap x --xml scan.xml            # ingest an existing nmap -oX
sploitmap 10.10.10.5 --nuclei         # LABS ONLY — nuclei web scan (see note)
sploitmap 10.10.10.5 --nuclei --deep  # LABS ONLY — nuclei full automatic scan
```

## What it does
1. **nmap -sV** — discover services + versions
2. **searchsploit** per versioned service — ranked (`[MSF]` module, `[hot]` RCE/backdoor)
3. **`--cve`** — nmap `vuln,vulners` NSE (version/CPE→CVE **and** protocol checks like SMB EternalBlue)
4. **research links** — per service, pre-filled exploit-db + NVD search URLs you click yourself
5. **`--nuclei`** (opt-in) — fingerprints web apps, recovers hidden versions (e.g. Tomcat under AppManager), runs CVE templates

Version-pinned matching by default so generic services (RPC/netbios) are skipped instead of returning noise. `--loose` for product-only.

## ⚠️ OSCP exam note
**Default `sploitmap` and `--cve` are exam-legal** (nmap NSE + searchsploit + manual research links — you do the research).

**`--nuclei` is LABS ONLY.** nuclei is an automated vulnerability scanner that also *exploits* (many templates trigger the bug to confirm it) — so it falls under the exam's banned "automated vulnerability scanner" **and** "automated exploitation tool" categories. It is **off by default** and prints a LAB-MODE warning. Never run it against exam machines. (Verify restrictions against your current OSCP exam guide.)

Requires: `nmap`, `searchsploit` (core); `nuclei` (only for `--nuclei`).
