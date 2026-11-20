# sploitmap

`nmap -sV` → per-service **exploit/CVE mapping**, nxc-style. Finds exploits; never runs them.

```bash
sploitmap 10.10.10.5                 # scan + map
sploitmap 10.10.10.5 --cve --full    # add CVE scripts, all ports
sploitmap targets.txt                # file of targets
sploitmap x --xml existing.xml       # ingest an nmap -oX file
```

For each service it runs `searchsploit` (offline ExploitDB) on the **product+version**,
ranks services with real exploits first (`[MSF]` = Metasploit module, `[hot]` = RCE/
backdoor/bypass), and prints the `searchsploit -m <id>` / `-x <id>` commands.

**Reliable by design:** only version-pinned services are searched — a bare
`Microsoft Windows RPC` with no version is skipped instead of returning 130
false matches. `--loose` searches product-only (noisier). `--cve` adds
`nmap --script vulners` (needs internet) / `vulscan` (offline, if installed).

Requires: `nmap`, `searchsploit`.
