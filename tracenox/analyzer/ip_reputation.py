"""Optional IP reputation lookups using the AbuseIPDB API.

This module never performs network requests automatically. Callers must
explicitly request a lookup and provide an API key.
"""

import ipaddress
import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
DEFAULT_TIMEOUT = 8


def classify_ip_address(address: str) -> dict:
    """Classify an IP address without contacting an external service."""
    try:
        parsed = ipaddress.ip_address(address.strip())
    except ValueError:
        return {
            "ip_address": address,
            "eligible_for_lookup": False,
            "status": "invalid_ip",
            "reason": "The value is not a valid IP address.",
        }

    if not parsed.is_global:
        return {
            "ip_address": str(parsed),
            "eligible_for_lookup": False,
            "status": "not_public",
            "reason": "Only globally routable public IP addresses can be checked.",
        }

    return {
        "ip_address": str(parsed),
        "eligible_for_lookup": True,
        "status": "pending",
        "reason": "Public IP address; external lookup has not been performed.",
    }


def lookup_abuseipdb(
    address: str,
    api_key: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict:
    """Look up one public IP address using AbuseIPDB.

    No lookup occurs without an explicit API key. Network and API failures
    are returned as status values rather than crashing log analysis.
    """
    result = classify_ip_address(address)

    if not result["eligible_for_lookup"]:
        return result

    key = (api_key or os.environ.get("ABUSEIPDB_API_KEY", "")).strip()
    if not key:
        return {
            **result,
            "status": "not_configured",
            "reason": "Set ABUSEIPDB_API_KEY to enable external reputation lookups.",
        }

    query = urlencode({
        "ipAddress": result["ip_address"],
        "maxAgeInDays": "90",
    })
    request = Request(
        f"{ABUSEIPDB_URL}?{query}",
        headers={
            "Key": key,
            "Accept": "application/json",
            "User-Agent": "TraceNox/0.1",
        },
        method="GET",
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))

        data = payload.get("data", {})
        return {
            "ip_address": result["ip_address"],
            "eligible_for_lookup": True,
            "status": "success",
            "provider": "AbuseIPDB",
            "checked_at_utc": __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ).isoformat(),
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "is_whitelisted": data.get("isWhitelisted"),
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "last_reported_at": data.get("lastReportedAt"),
        }
    except HTTPError as error:
        status = "rate_limited" if error.code == 429 else "provider_error"
        return {
            "ip_address": result["ip_address"],
            "eligible_for_lookup": True,
            "status": status,
            "reason": f"AbuseIPDB returned HTTP {error.code}.",
        }
    except (URLError, TimeoutError, OSError):
        return {
            "ip_address": result["ip_address"],
            "eligible_for_lookup": True,
            "status": "network_error",
            "reason": "Could not reach AbuseIPDB; check network connectivity.",
        }
    except (ValueError, TypeError, json.JSONDecodeError):
        return {
            "ip_address": result["ip_address"],
            "eligible_for_lookup": True,
            "status": "invalid_response",
            "reason": "AbuseIPDB returned an unreadable response.",
        }
