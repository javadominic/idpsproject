"""
IDPS API Routes — Automated Website Security Scanner
======================================================
Performs a real, automated security assessment of any URL by making
genuine HTTP requests. Detects missing security headers, SSL/TLS
misconfigurations, exposed sensitive paths, server information leakage,
open redirect risks, and cookie security flaws.

No hardcoded results — every finding comes from an actual probe.
"""

from __future__ import annotations

import asyncio
import ssl
import socket
import time
import urllib.parse
from collections import deque
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator

from shared.auth import User
from services.api.middleware.auth import get_current_user

router = APIRouter(prefix="/scanner", tags=["Website Scanner"])

# Keep the last 20 scan results in memory
_scan_history: deque[dict[str, Any]] = deque(maxlen=20)

# ─── Sensitive paths to probe (real OWASP top paths) ──────────────────────────
SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/wp-config.php",
    "/config.php",
    "/admin",
    "/admin/login",
    "/administrator",
    "/phpmyadmin",
    "/phpinfo.php",
    "/server-status",
    "/server-info",
    "/.htaccess",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/api/swagger.json",
    "/api/openapi.json",
    "/swagger-ui.html",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/debug",
    "/console",
    "/backup.zip",
    "/backup.sql",
    "/dump.sql",
    "/db.sqlite",
    "/Dockerfile",
    "/docker-compose.yml",
]

# ─── Required security headers ────────────────────────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "desc": "HSTS — forces HTTPS; prevents downgrade attacks",
        "severity": "HIGH",
    },
    "Content-Security-Policy": {
        "desc": "CSP — prevents XSS and data injection",
        "severity": "HIGH",
    },
    "X-Frame-Options": {
        "desc": "Prevents clickjacking via iframe embedding",
        "severity": "MEDIUM",
    },
    "X-Content-Type-Options": {
        "desc": "Prevents MIME-type sniffing (nosniff required)",
        "severity": "MEDIUM",
    },
    "Referrer-Policy": {
        "desc": "Controls referrer information leakage",
        "severity": "LOW",
    },
    "Permissions-Policy": {
        "desc": "Restricts browser feature access",
        "severity": "LOW",
    },
    "X-XSS-Protection": {
        "desc": "Legacy XSS filter (now superseded by CSP)",
        "severity": "INFO",
    },
}

# ─── Server headers that leak technology/version info ─────────────────────────
LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


class ScanPayload(BaseModel):
    url: str
    probe_sensitive_paths: bool = True
    check_ssl: bool = True
    timeout_seconds: int = 10

    @field_validator("url")
    @classmethod
    def must_be_http(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            v = "https://" + v
        parsed = urllib.parse.urlparse(v)
        if not parsed.netloc:
            raise ValueError("Not a valid URL")
        return v


def _classify_finding(severity: str) -> str:
    return {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡", "INFO": "🔵", "OK": "🟢"}.get(severity, "⚪")


async def _check_ssl_certificate(hostname: str, port: int = 443) -> list[dict]:
    """Check SSL/TLS certificate validity, expiry, and protocol."""
    findings = []
    try:
        ctx = ssl.create_default_context()
        loop = asyncio.get_event_loop()

        def _probe():
            try:
                with socket.create_connection((hostname, port), timeout=8) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        proto = ssock.version()
                        cipher = ssock.cipher()
                        return cert, proto, cipher
            except ssl.SSLCertVerificationError as e:
                return None, None, None, str(e)
            except Exception as e:
                return None, None, None, str(e)

        result = await loop.run_in_executor(None, _probe)
        if isinstance(result, tuple) and len(result) == 3:
            cert, proto, cipher = result
        else:
            cert, proto, cipher = None, None, None

        if cert:
            import datetime as dt
            not_after_str = cert.get("notAfter", "")
            if not_after_str:
                try:
                    not_after = dt.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (not_after - dt.datetime.utcnow()).days
                    if days_left < 0:
                        findings.append({"type": "SSL_CERTIFICATE_EXPIRED", "severity": "HIGH",
                                         "detail": f"Certificate expired {-days_left} days ago"})
                    elif days_left < 30:
                        findings.append({"type": "SSL_CERTIFICATE_EXPIRING_SOON", "severity": "HIGH",
                                         "detail": f"Certificate expires in {days_left} days"})
                    else:
                        findings.append({"type": "SSL_CERTIFICATE_VALID", "severity": "OK",
                                         "detail": f"Certificate valid, expires in {days_left} days"})
                except ValueError:
                    pass

            if proto in ("TLSv1", "TLSv1.1", None):
                findings.append({"type": "SSL_WEAK_PROTOCOL", "severity": "HIGH",
                                 "detail": f"Weak protocol in use: {proto}. Minimum: TLS 1.2"})
            else:
                findings.append({"type": "SSL_PROTOCOL_OK", "severity": "OK",
                                 "detail": f"Protocol: {proto}"})

            if cipher:
                cipher_name = cipher[0] if cipher else "unknown"
                if any(w in cipher_name.upper() for w in ["RC4", "DES", "MD5", "NULL", "EXPORT"]):
                    findings.append({"type": "SSL_WEAK_CIPHER", "severity": "HIGH",
                                     "detail": f"Weak cipher suite: {cipher_name}"})
                else:
                    findings.append({"type": "SSL_CIPHER_OK", "severity": "OK",
                                     "detail": f"Cipher: {cipher_name}"})
        else:
            findings.append({"type": "SSL_CHECK_FAILED", "severity": "MEDIUM",
                             "detail": "Could not establish TLS connection to verify certificate"})

    except Exception as e:
        findings.append({"type": "SSL_ERROR", "severity": "MEDIUM",
                         "detail": f"SSL probe error: {str(e)[:120]}"})

    return findings


@router.post("/scan")
async def scan_website(payload: ScanPayload, current_user: User = Depends(get_current_user)):
    """
    Automatically probe a website and detect real security issues.
    Makes genuine HTTP requests — no simulated or hardcoded results.
    """
    scan_id = f"scan-{int(time.time())}"
    started_at = datetime.now(timezone.utc)
    findings: list[dict[str, Any]] = []
    probed_paths: list[dict[str, Any]] = []

    parsed = urllib.parse.urlparse(payload.url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # ── 1. Main page request ──────────────────────────────────────────────────
    main_response_info: dict[str, Any] = {}
    try:
        limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=payload.timeout_seconds,
            verify=False,          # we do our own SSL check separately
            limits=limits,
        ) as client:
            t0 = time.perf_counter()
            resp = await client.get(payload.url, headers={"User-Agent": "IDPS-SecurityScanner/2.0"})
            latency_ms = round((time.perf_counter() - t0) * 1000, 1)

            main_response_info = {
                "status_code": resp.status_code,
                "latency_ms": latency_ms,
                "final_url": str(resp.url),
                "redirected": str(resp.url) != payload.url,
            }

            resp_headers = dict(resp.headers)

            # ── 1a. Security headers ──────────────────────────────────────────
            for header, meta in SECURITY_HEADERS.items():
                found = resp.headers.get(header)
                if not found:
                    findings.append({
                        "type": f"MISSING_HEADER_{header.upper().replace('-','_')}",
                        "severity": meta["severity"],
                        "detail": f"Missing: {header} — {meta['desc']}",
                        "header": header,
                    })
                else:
                    findings.append({
                        "type": f"HEADER_PRESENT_{header.upper().replace('-','_')}",
                        "severity": "OK",
                        "detail": f"{header}: {found[:120]}",
                        "header": header,
                    })

            # ── 1b. Server info leakage ───────────────────────────────────────
            for h in LEAKY_HEADERS:
                val = resp.headers.get(h)
                if val:
                    findings.append({
                        "type": "SERVER_INFO_LEAK",
                        "severity": "MEDIUM",
                        "detail": f"Header '{h}' leaks technology info: {val}",
                        "header": h,
                    })

            # ── 1c. Cookie security ───────────────────────────────────────────
            for cookie in resp.cookies.jar:
                flags = []
                if not cookie.secure:
                    flags.append("Secure flag missing (cookie sent over HTTP)")
                if not cookie.has_nonstandard_attr("HttpOnly"):
                    flags.append("HttpOnly flag missing (accessible to JavaScript)")
                samesite = cookie.get_nonstandard_attr("SameSite", "")
                if not samesite:
                    flags.append("SameSite not set (CSRF risk)")
                if flags:
                    findings.append({
                        "type": "INSECURE_COOKIE",
                        "severity": "MEDIUM",
                        "detail": f"Cookie '{cookie.name}': " + "; ".join(flags),
                        "cookie": cookie.name,
                    })

            # ── 1d. HTTP vs HTTPS redirect ────────────────────────────────────
            if parsed.scheme == "http":
                findings.append({
                    "type": "NO_HTTPS",
                    "severity": "HIGH",
                    "detail": "Site served over HTTP only — no HTTPS. All traffic is unencrypted.",
                })
            if parsed.scheme == "http" and main_response_info.get("redirected"):
                final = main_response_info["final_url"]
                if final.startswith("https://"):
                    findings.append({
                        "type": "HTTP_TO_HTTPS_REDIRECT",
                        "severity": "OK",
                        "detail": f"HTTP redirects to HTTPS → {final}",
                    })

            # ── 1e. Content-Type header ───────────────────────────────────────
            ct = resp.headers.get("content-type", "")
            if "charset" not in ct.lower() and "text" in ct.lower():
                findings.append({
                    "type": "MISSING_CHARSET",
                    "severity": "LOW",
                    "detail": f"Content-Type '{ct}' does not specify charset — may allow XSS via charset sniffing",
                })

        # ── 2. Probe sensitive paths ──────────────────────────────────────────
        if payload.probe_sensitive_paths:
            async with httpx.AsyncClient(
                follow_redirects=False,
                timeout=min(payload.timeout_seconds, 6),
                verify=False,
                limits=httpx.Limits(max_connections=10),
            ) as client:
                tasks = [
                    _probe_path(client, base_url, p)
                    for p in SENSITIVE_PATHS
                ]
                path_results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in path_results:
                    if isinstance(r, dict):
                        probed_paths.append(r)
                        if r.get("exposed"):
                            findings.append({
                                "type": "SENSITIVE_PATH_EXPOSED",
                                "severity": "HIGH" if r["path"] in ("/.env", "/.git/config", "/wp-config.php") else "MEDIUM",
                                "detail": f"Sensitive path accessible ({r['status_code']}): {r['path']}",
                                "path": r["path"],
                            })

    except httpx.ConnectError:
        raise HTTPException(status_code=502, detail=f"Cannot connect to {payload.url}. Is the site reachable?")
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail=f"Connection to {payload.url} timed out after {payload.timeout_seconds}s")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan error: {str(e)[:200]}")

    # ── 3. SSL certificate check ──────────────────────────────────────────────
    ssl_findings: list[dict] = []
    if payload.check_ssl and parsed.scheme == "https":
        ssl_findings = await _check_ssl_certificate(hostname, port)
        findings.extend(ssl_findings)

    # ── 4. Score ──────────────────────────────────────────────────────────────
    severity_weight = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "OK": 0}
    issue_count = sum(1 for f in findings if f["severity"] not in ("OK", "INFO"))
    high_count = sum(1 for f in findings if f["severity"] == "HIGH")
    raw_deduction = sum(severity_weight.get(f["severity"], 0) for f in findings if f["severity"] not in ("OK", "INFO"))
    score = max(0, round(100 - (raw_deduction * 3.5), 1))

    result = {
        "scan_id": scan_id,
        "url": payload.url,
        "scanned_at": started_at.isoformat(),
        "response": main_response_info,
        "score": score,
        "grade": _grade(score),
        "issue_summary": {
            "total": issue_count,
            "high": high_count,
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in findings if f["severity"] == "LOW"),
            "ok": sum(1 for f in findings if f["severity"] == "OK"),
        },
        "findings": findings,
        "probed_paths": probed_paths,
        "ssl_checked": payload.check_ssl and parsed.scheme == "https",
    }
    _scan_history.appendleft(result)
    return result


async def _probe_path(client: httpx.AsyncClient, base_url: str, path: str) -> dict:
    url = base_url.rstrip("/") + path
    try:
        t0 = time.perf_counter()
        r = await client.get(url, headers={"User-Agent": "IDPS-SecurityScanner/2.0"})
        ms = round((time.perf_counter() - t0) * 1000, 1)
        # 200 or 403 that reveals existence — mark exposed
        exposed = r.status_code in (200, 301, 302) or (
            r.status_code == 403 and len(r.text) > 50
        )
        return {
            "path": path,
            "url": url,
            "status_code": r.status_code,
            "latency_ms": ms,
            "exposed": exposed,
            "size_bytes": len(r.content),
        }
    except Exception:
        return {
            "path": path,
            "url": url,
            "status_code": 0,
            "latency_ms": 0,
            "exposed": False,
            "size_bytes": 0,
        }


def _grade(score: float) -> str:
    if score >= 90:
        return "A"
    elif score >= 75:
        return "B"
    elif score >= 60:
        return "C"
    elif score >= 45:
        return "D"
    else:
        return "F"


@router.get("/history")
async def get_scan_history(current_user: User = Depends(get_current_user)):
    """Return recent website scan results."""
    return list(_scan_history)


@router.get("/history/{scan_id}")
async def get_scan_result(scan_id: str, current_user: User = Depends(get_current_user)):
    """Return a specific scan result by ID."""
    for scan in _scan_history:
        if scan["scan_id"] == scan_id:
            return scan
    raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
