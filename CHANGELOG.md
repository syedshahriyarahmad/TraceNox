# Changelog

Notable changes to TraceNox are documented here.

## 0.2.0

- Validate IPv4 and IPv6 source addresses before creating SSH authentication events.
- Ignore malformed source addresses rather than treating them as valid IP evidence.
- Add parser regression tests for IPv4, IPv6, malformed addresses, and unrelated lines.
- Add security reporting guidance and contribution instructions.
