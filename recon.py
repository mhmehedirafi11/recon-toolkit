#!/usr/bin/env python3
"""
recon.py — a small, dependency-free reconnaissance helper for authorised security testing.

What it does
------------
1. Passive subdomain discovery from certificate transparency logs (crt.sh).
2. DNS resolution of every discovered host (deduplicated, sorted).
3. HTTP/HTTPS probing: status code, redirect target, server header, page title.
4. Optional TCP port check against a list of ports.
5. Report output as a console table, plus optional Markdown and JSON files.

Why standard library only
-------------------------
No pip install, no virtualenv, no version conflicts. It runs on any Python 3.9+
installation, including a fresh Kali/Ubuntu box, which matters when you are on an
assessment laptop you do not control.

Authorised use only
-------------------
This tool performs *active* requests against the target you name. Only run it against
domains you own or have explicit written permission to test. See README.md.

Usage
-----
    python3 recon.py --domain example.com
    python3 recon.py --domain example.com --ports 22,80,443,8080 --threads 30
    python3 recon.py --domain example.com --md report.md --json report.json

Tip: keep the default thread count modest. Public services may rate-limit you, and
being a good citizen on the internet is part of doing this professionally.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Iterable, List, Optional

USER_AGENT = "recon-toolkit/1.0 (+https://github.com/mhmehedirafi11/recon-toolkit)"
CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
HTTP_TIMEOUT = 8
DNS_TIMEOUT = 5

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


# --------------------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------------------
@dataclass
class HostResult:
    """Everything we learned about a single hostname."""

    host: str
    ips: List[str] = field(default_factory=list)
    resolved: bool = False
    scheme: Optional[str] = None
    status: Optional[int] = None
    redirect: Optional[str] = None
    server: Optional[str] = None
    title: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def url(self) -> str:
        if self.scheme:
            return f"{self.scheme}://{self.host}"
        return f"http://{self.host}"


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------
def eprint(*args: object) -> None:
    """Progress goes to stderr so stdout can be piped cleanly."""
    print(*args, file=sys.stderr)


def fetch(url: str, timeout: int = HTTP_TIMEOUT) -> bytes:
    """Minimal GET that always sends a proper User-Agent."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        return response.read()


def passive_subdomains(domain: str) -> List[str]:
    """
    Collect hostnames from certificate transparency logs.

    crt.sh returns one JSON object per certificate; the interesting field is
    ``name_value`` which may contain several newline-separated names and wildcards.
    """
    url = CRT_SH_URL.format(domain=urllib.parse.quote(domain))
    try:
        raw = fetch(url, timeout=25)
        records = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception as exc:  # network hiccup, rate limit, malformed JSON
        eprint(f"  [!] certificate transparency lookup failed: {exc}")
        eprint("  [!] continuing with the apex domain only")
        return [domain]

    names: set[str] = set()
    for record in records:
        for value in str(record.get("name_value", "")).splitlines():
            value = value.strip().lower().lstrip("*.").rstrip(".")
            if value.endswith(domain) and " " not in value:
                names.add(value)

    names.add(domain)
    return sorted(names)


def resolve(host: str) -> List[str]:
    """Resolve a hostname to a sorted list of unique IPv4/IPv6 addresses."""
    try:
        socket.setdefaulttimeout(DNS_TIMEOUT)
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, socket.timeout, UnicodeError):
        return []
    return sorted({info[4][0] for info in infos})


def check_port(host: str, port: int, timeout: float = 3.0) -> bool:
    """True if a TCP connection to host:port succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_http(host: str) -> tuple[Optional[str], Optional[int], Optional[str], Optional[str], Optional[str]]:
    """
    Probe a host over HTTPS, falling back to HTTP.

    Returns ``(scheme, status, redirect, server, title)``. Only the headers and a small
    slice of the body are read, so this stays fast and light on the target.
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            # A final handler tells urllib not to follow redirects, so we can report them.
            opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=context))
            with opener.open(request, timeout=HTTP_TIMEOUT) as response:
                body = response.read(65536).decode("utf-8", errors="replace")
                title = TITLE_RE.search(body)
                return (
                    scheme,
                    response.status,
                    None,
                    response.headers.get("Server"),
                    title.group(1).strip()[:120] if title else None,
                )
        except urllib.error.HTTPError as exc:
            body = b""
            try:
                body = exc.read(65536)
            except Exception:
                pass
            title = TITLE_RE.search(body.decode("utf-8", errors="replace"))
            return (
                scheme,
                exc.code,
                exc.headers.get("Location"),
                exc.headers.get("Server"),
                title.group(1).strip()[:120] if title else None,
            )
        except (urllib.error.URLError, ssl.SSLError, ConnectionError, TimeoutError, UnicodeError):
            continue  # try the next scheme
    return None, None, None, None, None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Report redirects instead of silently following them."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


# --------------------------------------------------------------------------------------
# Pipeline
# --------------------------------------------------------------------------------------
def scan_host(host: str, ports: Iterable[int]) -> HostResult:
    result = HostResult(host=host)
    result.ips = resolve(host)
    result.resolved = bool(result.ips)

    if not result.resolved:
        result.error = "dns resolution failed"
        return result

    scheme, status, redirect, server, title = probe_http(host)
    result.scheme = scheme
    result.status = status
    result.redirect = redirect
    result.server = server
    result.title = title
    if scheme is None:
        result.error = "no http/https response"

    for port in ports:
        if check_port(host, port):
            result.open_ports.append(port)

    return result


def run(domain: str, ports: List[int], threads: int) -> List[HostResult]:
    eprint(f"[*] target      : {domain}")
    eprint("[*] phase 1/3   : passive subdomain discovery (crt.sh)")
    hosts = passive_subdomains(domain)
    eprint(f"[+] {len(hosts)} hostname(s) discovered")

    eprint(f"[*] phase 2/3   : resolving, probing HTTP and checking {len(ports)} port(s)")
    results: List[HostResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futures = {pool.submit(scan_host, host, ports): host for host in hosts}
        for future in concurrent.futures.as_completed(futures):
            host = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:  # never let one host kill the run
                results.append(HostResult(host=host, error=f"unexpected error: {exc}"))
            eprint(f"    - done: {host}")

    results.sort(key=lambda r: (not r.resolved, r.host))
    eprint("[*] phase 3/3   : building report")
    return results


# --------------------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------------------
def print_table(results: List[HostResult]) -> None:
    header = f"{'HOST':<44} {'IP':<16} {'ST':<5} {'SERVER':<18} PORTS"
    print(header)
    print("-" * len(header))
    for r in results:
        ip = r.ips[0] if r.ips else "-"
        status = str(r.status) if r.status else ("dns-fail" if not r.resolved else "-")
        server = (r.server or "-")[:17]
        ports = ",".join(str(p) for p in r.open_ports) or "-"
        print(f"{r.host:<44} {ip:<16} {status:<5} {server:<18} {ports}")

    live = sum(1 for r in results if r.scheme)
    print(
        f"\n{len(results)} host(s) · {sum(1 for r in results if r.resolved)} resolved · "
        f"{live} serving HTTP(S)"
    )


def to_markdown(domain: str, results: List[HostResult]) -> str:
    lines = [
        f"# Reconnaissance report — `{domain}`",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "## Summary",
        "",
        f"- Hostnames discovered: **{len(results)}**",
        f"- Resolved: **{sum(1 for r in results if r.resolved)}**",
        f"- Serving HTTP(S): **{sum(1 for r in results if r.scheme)}**",
        "",
        "## Hosts",
        "",
        "| Host | IP | Scheme | Status | Server | Title | Open ports |",
        "|:--|:--|:--|:--|:--|:--|:--|",
    ]
    for r in results:
        lines.append(
            "| {host} | {ip} | {scheme} | {status} | {server} | {title} | {ports} |".format(
                host=f"`{r.host}`",
                ip=r.ips[0] if r.ips else "—",
                scheme=r.scheme or "—",
                status=r.status if r.status else "—",
                server=(r.server or "—").replace("|", "/"),
                title=(r.title or "—").replace("|", "/"),
                ports=", ".join(str(p) for p in r.open_ports) or "—",
            )
        )
    lines += [
        "",
        "## Notes",
        "",
        "Passive discovery uses certificate transparency logs, so it only surfaces hostnames that",
        "appear in a published certificate. Absence of a host in this report is not proof that it",
        "does not exist — pair this with active DNS enumeration and virtual-host discovery.",
        "",
        "> Generated with [recon-toolkit](https://github.com/mhmehedirafi11/recon-toolkit).",
    ]
    return "\n".join(lines) + "\n"


def to_json(domain: str, results: List[HostResult]) -> str:
    payload = {
        "target": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "host_count": len(results),
        "hosts": [asdict(r) for r in results],
    }
    return json.dumps(payload, indent=2) + "\n"


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Passive subdomain discovery, HTTP probing and port checks for authorised testing.",
        epilog="Only test systems you own or have written permission to assess.",
    )
    parser.add_argument("-d", "--domain", required=True, help="apex domain, e.g. example.com")
    parser.add_argument(
        "-p",
        "--ports",
        default="80,443,22,8080",
        help="comma-separated ports to check (default: 80,443,22,8080)",
    )
    parser.add_argument("-t", "--threads", type=int, default=15, help="worker threads (default: 15)")
    parser.add_argument("--md", metavar="FILE", help="write a Markdown report to FILE")
    parser.add_argument("--json", metavar="FILE", help="write a JSON report to FILE")
    parser.add_argument("--quiet", action="store_true", help="hide the console table")
    return parser.parse_args(argv)


def parse_ports(value: str) -> List[int]:
    ports: List[int] = []
    for chunk in value.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if not chunk.isdigit() or not 1 <= int(chunk) <= 65535:
            raise argparse.ArgumentTypeError(f"invalid port: {chunk}")
        ports.append(int(chunk))
    return sorted(set(ports))


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    domain = args.domain.strip().lower().removeprefix("https://").removeprefix("http://").strip("/")
    if not domain or "." not in domain:
        eprint("[!] please provide a valid apex domain, e.g. example.com")
        return 2

    try:
        ports = parse_ports(args.ports)
    except argparse.ArgumentTypeError as exc:
        eprint(f"[!] {exc}")
        return 2

    results = run(domain, ports, args.threads)

    if not args.quiet:
        print()
        print_table(results)

    if args.md:
        with open(args.md, "w", encoding="utf-8") as handle:
            handle.write(to_markdown(domain, results))
        eprint(f"[+] markdown report: {args.md}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            handle.write(to_json(domain, results))
        eprint(f"[+] json report    : {args.json}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        eprint("\n[!] interrupted")
        raise SystemExit(130)
