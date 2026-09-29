import json
from unittest.mock import patch

from tracenox.analyzer.ip_reputation import (
    classify_ip_address,
    lookup_abuseipdb,
)


def test_classify_public_ip_without_network():
    result = classify_ip_address("8.8.8.8")

    assert result["eligible_for_lookup"] is True
    assert result["status"] == "pending"


def test_private_ip_is_not_sent_to_provider():
    result = lookup_abuseipdb("192.168.1.10", api_key="test-key")

    assert result["eligible_for_lookup"] is False
    assert result["status"] == "not_public"


def test_invalid_ip_is_rejected():
    result = lookup_abuseipdb("not-an-ip", api_key="test-key")

    assert result["status"] == "invalid_ip"


def test_missing_api_key_skips_external_lookup():
    with patch("tracenox.analyzer.ip_reputation.urlopen") as mocked_urlopen:
        result = lookup_abuseipdb("8.8.8.8", api_key="")

    assert result["status"] == "not_configured"
    mocked_urlopen.assert_not_called()


def test_successful_lookup_parses_provider_data():
    payload = {
        "data": {
            "abuseConfidenceScore": 25,
            "totalReports": 4,
            "isWhitelisted": None,
            "countryCode": "US",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Example ISP",
            "domain": "example.com",
            "lastReportedAt": None,
        }
    }

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps(payload).encode("utf-8")

    with patch(
        "tracenox.analyzer.ip_reputation.urlopen",
        return_value=FakeResponse(),
    ):
        result = lookup_abuseipdb("8.8.8.8", api_key="test-key")

    assert result["status"] == "success"
    assert result["provider"] == "AbuseIPDB"
    assert result["abuse_confidence_score"] == 25
    assert result["total_reports"] == 4


def test_network_error_is_reported_without_crashing():
    from urllib.error import URLError

    with patch(
        "tracenox.analyzer.ip_reputation.urlopen",
        side_effect=URLError("offline"),
    ):
        result = lookup_abuseipdb("8.8.8.8", api_key="test-key")

    assert result["status"] == "network_error"
