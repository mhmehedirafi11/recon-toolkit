# recon-toolkit

A small, **dependency-free** reconnaissance helper for authorised security testing: passive subdomain
discovery, DNS resolution, HTTP/HTTPS probing and TCP port checks — with a clean Markdown/JSON report at
the end.

```
$ python3 recon.py --domain example.com --ports 80,443 --md report.md

HOST                       IP               ST    SERVER             PORTS
--------------------------------------------------------------------------
example.com                104.20.23.154    200   cloudflare         443

1 host(s) · 1 resolved · 1 serving HTTP(S)
```

---

## Why another recon script?

- **Zero dependencies.** Standard library only — no `pip install`, no virtualenv, nothing to break on
  a locked-down assessment laptop. Just Python 3.9+.
- **Report-ready output.** It writes a Markdown table and a JSON file you can paste straight into an
  engagement note or feed into another script.
- **Polite by default.** Modest thread count, short timeouts, small body reads. It gathers enough to
  make decisions without hammering the target.

## Features

| Step | What happens |
|:--|:--|
| 1. Passive discovery | Pulls hostnames from **certificate transparency logs (crt.sh)** — no traffic to the target at all |
| 2. DNS resolution | Resolves every hostname, de-duplicates IPv4/IPv6 addresses |
| 3. HTTP probe | Tries HTTPS then HTTP; records status code, redirect target, `Server` header and page `<title>` |
| 4. Port check | TCP connect test against the ports you specify |
| 5. Reporting | Console table + optional Markdown and JSON reports |

## Requirements

- Python **3.9+**
- No third-party packages

## Usage

```bash
# basic run — apex domain, default ports (80,443,22,8080)
python3 recon.py --domain example.com

# custom ports and more threads
python3 recon.py --domain example.com --ports 22,80,443,8080,8443 --threads 30

# write reports
python3 recon.py --domain example.com --md report.md --json report.json

# skip the console table when piping output
python3 recon.py --domain example.com --quiet --json report.json
```

### All options

| Flag | Description | Default |
|:--|:--|:--|
| `-d`, `--domain` | Apex domain to assess (required) | — |
| `-p`, `--ports` | Comma-separated TCP ports to test | `80,443,22,8080` |
| `-t`, `--threads` | Worker threads | `15` |
| `--md FILE` | Write a Markdown report | off |
| `--json FILE` | Write a JSON report | off |
| `--quiet` | Hide the console table | off |

## Sample output

Markdown reports look like this:

```markdown
## Hosts

| Host | IP | Scheme | Status | Server | Title | Open ports |
|:--|:--|:--|:--|:--|:--|:--|
| `example.com` | 104.20.23.154 | https | 200 | cloudflare | Example Domain | 443 |
```

## How it fits into a workflow

This is the **reconnaissance** stage only. A typical assessment continues with:

1. `recon.py` — passive discovery and first-pass fingerprinting *(this tool)*
2. Active DNS enumeration and virtual-host discovery
3. Service/version enumeration (Nmap, service-specific tooling)
4. Vulnerability identification and controlled exploitation
5. Risk-rated reporting, remediation and retest

See the companion repository
[**vapt-checklist**](https://github.com/mhmehedirafi11/vapt-checklist) for the assessment checklists and the
finding report template I use for steps 3–5.

## Legal notice — read this first

This tool makes **active network requests**. Run it **only** against systems you own or for which you hold
explicit **written authorisation** naming the targets and the testing window. Unauthorised scanning is
illegal in most jurisdictions and unprofessional everywhere.

The author accepts no liability for misuse or for any damage caused by this software.

## Roadmap

- [ ] Screenshot capture of live HTTP(S) services
- [ ] TLS certificate detail extraction (issuer, expiry, SANs)
- [ ] Optional virtual-host discovery from a wordlist
- [ ] CSV output

## License

[MIT](LICENSE) © 2026 Mehedi Rafi

## Contact

- GitHub: [@mhmehedirafi11](https://github.com/mhmehedirafi11)
- LinkedIn: [mehedi-rafi](https://www.linkedin.com/in/mehedi-rafi)
