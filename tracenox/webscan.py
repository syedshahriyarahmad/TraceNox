"""Low-impact website security assessment for authorized targets."""

from __future__ import annotations

import argparse
import html
import ipaddress
import json
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
)


USER_AGENT = "TraceNox-WebAssessment/0.3.0"
MAX_REDIRECTS = 5
TIMEOUT_SECONDS = 8
MAX_BODY_BYTES = 65536

SECURITY_HEADERS = {
    "strict-transport-security": (
        "HSTS",
        "Helps enforce HTTPS after a browser has learned the policy.",
    ),
    "content-security-policy": (
        "Content Security Policy",
        "Helps restrict browser resource loading.",
    ),
    "x-content-type-options": (
        "Content type protection",
        "Helps prevent MIME-type sniffing.",
    ),
    "referrer-policy": (
        "Referrer policy",
        "Controls referrer information sent by browsers.",
    ),
    "permissions-policy": (
        "Permissions policy",
        "Restricts access to selected browser features.",
    ),
}


class NoRedirectHandler(HTTPRedirectHandler):
    """Return redirect responses to the scanner instead of following blindly."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def normalize_url(value: str) -> str:
    """Validate and normalize an HTTP(S) URL."""
    value = value.strip()
    if not value:
        raise ValueError("URL cannot be empty.")

    if "://" not in value:
        value = "https://" + value

    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only http:// and https:// URLs are supported.")
    if not parsed.hostname:
        raise ValueError("URL must include a hostname.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing embedded credentials are not allowed.")
    if parsed.port is not None and not (1 <= parsed.port <= 65535):
        raise ValueError("Invalid port.")

    host = parsed.hostname.rstrip(".").lower()
    if not host or any(ch.isspace() for ch in host):
        raise ValueError("Invalid hostname.")

    # Reject localhost names before DNS resolution.
    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError("Localhost targets are not allowed.")

    # Reject local hostnames and IP literals that are not public.
    try:
        literal_ip = ipaddress.ip_address(host)
    except ValueError:
        literal_ip = None

    if literal_ip is not None and not literal_ip.is_global:
        raise ValueError("Private, loopback, link-local, and reserved IPs are blocked.")

    netloc = host
    if ":" in host and not host.startswith("["):
        netloc = f"[{host}]"
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"

    path = parsed.path or "/"
    return urlunsplit(
        (parsed.scheme.lower(), netloc, path, parsed.query, "")
    )


def resolve_public_addresses(hostname: str, port: int) -> list[str]:
    """Resolve a hostname and refuse it if any result is non-public."""
    try:
        literal = ipaddress.ip_address(hostname)
        addresses = [str(literal)]
    except ValueError:
        try:
            results = socket.getaddrinfo(
                hostname, port, type=socket.SOCK_STREAM
            )
        except socket.gaierror as exc:
            raise ValueError(f"DNS resolution failed: {exc}") from exc

        addresses = sorted({item[4][0] for item in results})

    if not addresses:
        raise ValueError("Hostname did not resolve to an IP address.")

    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ValueError(
                f"Target resolves to a non-public address ({address}); blocked."
            )

    return addresses


def _finding(findings, severity, title, evidence, recommendation):
    findings.append(
        {
            "severity": severity,
            "title": title,
            "evidence": str(evidence),
            "recommendation": recommendation,
        }
    )


def _tls_details(hostname: str, port: int) -> dict:
    """Read the public TLS certificate without sending application data."""
    context = ssl.create_default_context()
    with socket.create_connection(
        (hostname, port), timeout=TIMEOUT_SECONDS
    ) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=hostname) as tls:
            cert = tls.getpeercert()
            cipher = tls.cipher()
            not_after = cert.get("notAfter")
            expiry = None
            days_remaining = None

            if not_after:
                expires = datetime.strptime(
                    not_after, "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)
                expiry = expires.isoformat()
                days_remaining = (expires - datetime.now(timezone.utc)).days

            subject = cert.get("subject", [])
            issuer = cert.get("issuer", [])

            def flatten(items):
                return [
                    f"{key}={value}"
                    for group in items
                    for key, value in group
                ]

            return {
                "tls_version": tls.version(),
                "cipher": cipher[0] if cipher else None,
                "subject": flatten(subject),
                "issuer": flatten(issuer),
                "expires_at": expiry,
                "days_remaining": days_remaining,
            }


def _request_once(url: str):
    request = Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.5",
            "Connection": "close",
        },
        method="GET",
    )
    opener = build_opener(NoRedirectHandler())
    try:
        response = opener.open(request, timeout=TIMEOUT_SECONDS)
        try:
            body = response.read(MAX_BODY_BYTES)
            return response.status, response.headers, body
        finally:
            response.close()
    except HTTPError as exc:
        try:
            body = exc.read(MAX_BODY_BYTES)
            return exc.code, exc.headers, body
        finally:
            exc.close()


def scan_website(target: str) -> dict:
    """Run low-impact DNS, HTTP headers, cookies, redirect, and TLS checks."""
    findings = []
    started = time.monotonic()
    current_url = normalize_url(target)
    original_url = current_url
    redirects = []
    response_data = None
    tls_info = None
    resolved = []

    for hop in range(MAX_REDIRECTS + 1):
        parsed = urlsplit(current_url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # Resolve and check every redirect destination independently.
        resolved = resolve_public_addresses(host, port)

        if parsed.scheme == "https":
            try:
                tls_info = _tls_details(host, port)
                if tls_info.get("days_remaining") is not None:
                    if tls_info["days_remaining"] < 0:
                        _finding(
                            findings, "high", "TLS certificate expired",
                            tls_info["expires_at"],
                            "Renew the certificate and confirm the full certificate chain.",
                        )
                    elif tls_info["days_remaining"] <= 21:
                        _finding(
                            findings, "medium", "TLS certificate expires soon",
                            f"{tls_info['days_remaining']} days remaining",
                            "Renew the certificate before its expiry date.",
                        )
            except (OSError, ssl.SSLError, ValueError) as exc:
                _finding(
                    findings, "high", "TLS validation failed",
                    str(exc),
                    "Check certificate validity, hostname matching, trust chain, and TLS configuration.",
                )
                tls_info = {"error": str(exc)}

        try:
            status, headers, body = _request_once(current_url)
        except (OSError, URLError, TimeoutError, ValueError) as exc:
            _finding(
                findings, "info", "HTTP request failed",
                str(exc),
                "Check connectivity, DNS, firewall rules, and whether the target is available.",
            )
            response_data = {"error": str(exc)}
            break

        location = headers.get("Location")
        if status in {301, 302, 303, 307, 308} and location:
            destination = urljoin(current_url, location)
            redirects.append(
                {"status": status, "from": current_url, "to": destination}
            )
            try:
                next_url = normalize_url(destination)
            except ValueError as exc:
                _finding(
                    findings, "medium", "Redirect destination rejected",
                    f"{destination}: {exc}",
                    "Review the redirect target and ensure it points to an intended public URL.",
                )
                response_data = {
                    "status": status,
                    "headers": dict(headers.items()),
                    "body_bytes_read": len(body),
                }
                break

            if hop >= MAX_REDIRECTS:
                _finding(
                    findings, "medium", "Redirect limit reached",
                    f"More than {MAX_REDIRECTS} redirects",
                    "Remove unnecessary redirect chains and check for redirect loops.",
                )
                response_data = {"status": status, "headers": dict(headers.items())}
                break

            current_url = next_url
            continue

        response_data = {
            "status": status,
            "headers": dict(headers.items()),
            "body_bytes_read": len(body),
            "content_type": headers.get("Content-Type"),
            "server_header": headers.get("Server"),
        }
        break

    headers = (
        response_data.get("headers", {})
        if response_data and isinstance(response_data.get("headers"), dict)
        else {}
    )
    normalized_headers = {key.lower(): value for key, value in headers.items()}

    for header, (label, description) in SECURITY_HEADERS.items():
        if header not in normalized_headers:
            severity = "medium" if header in {
                "strict-transport-security", "content-security-policy"
            } else "low"
            _finding(
                findings, severity, f"Missing {label} header",
                f"HTTP response does not include {header}.",
                description + " Configure the header after testing application compatibility.",
            )

    if response_data and response_data.get("status") == 200:
        _finding(
            findings, "info", "HTTP endpoint responded",
            f"Final URL: {current_url}",
            "Review the other findings and validate them against the application's requirements.",
        )

    set_cookie_values = []
    if response_data:
        for key, value in headers.items():
            if key.lower() == "set-cookie":
                set_cookie_values.append(value)

    for cookie in set_cookie_values:
        cookie_lower = cookie.lower()
        cookie_name = cookie.split("=", 1)[0].strip() or "(unnamed)"
        missing = []
        if "secure" not in cookie_lower:
            missing.append("Secure")
        if "httponly" not in cookie_lower:
            missing.append("HttpOnly")
        if "samesite" not in cookie_lower:
            missing.append("SameSite")
        if missing:
            _finding(
                findings, "low", f"Cookie attributes missing: {cookie_name}",
                ", ".join(missing),
                "Set appropriate Secure, HttpOnly, and SameSite attributes based on cookie purpose.",
            )

    if urlsplit(original_url).scheme == "http":
        _finding(
            findings, "medium", "Target URL uses HTTP",
            original_url,
            "Serve the site over HTTPS and redirect HTTP requests to HTTPS.",
        )

    if redirects and urlsplit(original_url).scheme == "http":
        final_scheme = urlsplit(current_url).scheme
        if final_scheme != "https":
            _finding(
                findings, "medium", "HTTP did not finish on HTTPS",
                f"Final URL: {current_url}",
                "Review the redirect chain and configure a permanent HTTPS redirect.",
            )

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda item: severity_order.get(item["severity"], 5))

    return {
        "tool": "TraceNox Website Assessment",
        "version": "0.3.0",
        "scan_started_at": datetime.now(timezone.utc).isoformat(),
        "target": original_url,
        "final_url": current_url,
        "resolved_ips": resolved,
        "http": response_data,
        "tls": tls_info,
        "redirects": redirects,
        "findings": findings,
        "summary": {
            "total_findings": len(findings),
            "by_severity": {
                severity: sum(
                    1 for finding in findings
                    if finding["severity"] == severity
                )
                for severity in ("critical", "high", "medium", "low", "info")
            },
            "duration_seconds": round(time.monotonic() - started, 3),
        },
        "limitations": [
            "This is a low-impact surface assessment, not a full penetration test.",
            "No authentication bypass, injection payloads, brute force, or exploit attempts are performed.",
            "A missing header is a configuration observation, not proof of a vulnerability.",
            "DNS results can change between validation and connection; use only authorized targets.",
        ],
    }


def generate_html_report(result: dict) -> str:
    """Generate a self-contained HTML report with escaped evidence."""
    def esc(value):
        return html.escape(str(value))

    rows = []
    for finding in result.get("findings", []):
        rows.append(
            "<tr>"
            f"<td>{esc(finding.get('severity'))}</td>"
            f"<td>{esc(finding.get('title'))}</td>"
            f"<td>{esc(finding.get('evidence'))}</td>"
            f"<td>{esc(finding.get('recommendation'))}</td>"
            "</tr>"
        )

    summary = result.get("summary", {})
    severity_rows = "".join(
        f"<li><strong>{esc(key.title())}:</strong> {esc(value)}</li>"
        for key, value in summary.get("by_severity", {}).items()
    )
    limitations = "".join(
        f"<li>{esc(item)}</li>" for item in result.get("limitations", [])
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TraceNox Website Assessment</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:1200px;margin:2rem auto;padding:0 1rem;line-height:1.5}}
table{{border-collapse:collapse;width:100%;overflow-wrap:anywhere}}
th,td{{border:1px solid #ccc;padding:.65rem;text-align:left;vertical-align:top}}
th{{background:#eee}} code{{overflow-wrap:anywhere}}
.notice{{padding:1rem;border:1px solid #c90;border-radius:.5rem}}
</style>
</head>
<body>
<h1>TraceNox Website Assessment</h1>
<div class="notice"><strong>Scope:</strong> Low-impact surface checks only.
This report does not establish that a website is secure or vulnerable.</div>
<p><strong>Target:</strong> <code>{esc(result.get('target'))}</code></p>
<p><strong>Final URL:</strong> <code>{esc(result.get('final_url'))}</code></p>
<p><strong>Resolved IPs:</strong> {esc(", ".join(result.get("resolved_ips", [])))}</p>
<h2>Summary</h2>
<p><strong>Total findings:</strong> {esc(summary.get('total_findings', 0))}</p>
<ul>{severity_rows}</ul>
<h2>HTTP response</h2>
<pre>{esc(json.dumps(result.get('http'), indent=2, ensure_ascii=False))}</pre>
<h2>TLS details</h2>
<pre>{esc(json.dumps(result.get('tls'), indent=2, ensure_ascii=False))}</pre>
<h2>Redirect chain</h2>
<pre>{esc(json.dumps(result.get('redirects'), indent=2, ensure_ascii=False))}</pre>
<h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>Recommendation</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan="4">No findings were generated.</td></tr>'}</tbody></table>
<h2>Limitations</h2><ul>{limitations}</ul>
<p>Generated by TraceNox {esc(result.get('version'))}.</p>
</body></html>"""


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="tracenox-web",
        description="Low-impact website security assessment for authorized targets.",
    )
    parser.add_argument("url", help="Authorized public HTTP(S) URL or domain")
    parser.add_argument("--json", dest="json_path", help="Write JSON report to this file")
    parser.add_argument("--html", dest="html_path", help="Write HTML report to this file")
    args = parser.parse_args(argv)

    try:
        result = scan_website(args.url)
    except (ValueError, OSError, ssl.SSLError) as exc:
        print(f"TraceNox web assessment error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(result["summary"], indent=2))
    print(f"Target: {result['target']}")
    print(f"Final URL: {result['final_url']}")
    print(f"Findings: {result['summary']['total_findings']}")

    if args.json_path:
        Path(args.json_path).write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"JSON report saved: {args.json_path}")

    if args.html_path:
        Path(args.html_path).write_text(
            generate_html_report(result), encoding="utf-8"
        )
        print(f"HTML report saved: {args.html_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
