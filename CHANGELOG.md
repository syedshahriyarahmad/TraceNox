# Changelog

Notable changes to TraceNox are documented here.

## 0.2.0

- Validate IPv4 and IPv6 source addresses before creating SSH authentication events.
- Ignore malformed source addresses rather than treating them as valid IP evidence.
- Add parser regression tests for IPv4, IPv6, malformed addresses, and unrelated lines.
- Add security reporting guidance and contribution instructions.

## 0.3.0

- Add low-impact website surface assessment for authorized public HTTP(S) targets.
- Add DNS resolution, redirect-chain inspection, HTTP security-header checks,
  cookie-attribute observations, and TLS certificate metadata.
- Add JSON and self-contained HTML reports.
- Block non-public IP addresses and reject credential-bearing URLs.
- Add website-assessment validation and report-escaping regression tests.
