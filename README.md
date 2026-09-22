# TraceNox

**Evidence-Driven Cybersecurity Investigation Toolkit**

TraceNox is a Python-based cybersecurity investigation toolkit designed to analyze real security logs, extract authentication events, detect suspicious activity, and generate clear investigation reports.

## Current Capabilities

- Read Linux authentication log files
- Parse SSH authentication events
- Identify failed SSH login attempts
- Detect repeated failed logins from the same source IP
- Preserve raw log evidence
- Generate human-readable security reports
- Run from the command line
- Work with real log files instead of hard-coded results

## Current Detection

### SSH Failed Login Burst

TraceNox identifies repeated failed SSH authentication attempts from the same source IP.

Example:

```text
Source IP      : 192.168.1.50
Failed attempts: 5
Threshold      : 5
Severity       : HIGH

