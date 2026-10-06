"""Linux security hardening checks for TraceNox."""

from __future__ import annotations

import shutil
import stat
import subprocess
from pathlib import Path


def _run(command: list[str]) -> tuple[int, str]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return result.returncode, result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return 1, ""


def _result(
    check_id: str,
    title: str,
    status: str,
    severity: str,
    detail: str,
    recommendation: str,
) -> dict:
    return {
        "id": check_id,
        "title": title,
        "status": status,
        "severity": severity,
        "detail": detail,
        "recommendation": recommendation,
    }


def _check_ssh_root_login() -> dict:
    path = Path("/etc/ssh/sshd_config")

    if not path.exists():
        return _result(
            "ssh_root_login",
            "SSH root login",
            "UNKNOWN",
            "INFO",
            "OpenSSH server configuration was not found.",
            "Review SSH hardening manually if SSH is used.",
        )

    value = None

    try:
        for raw in path.read_text(
            encoding="utf-8",
            errors="ignore",
        ).splitlines():
            line = raw.strip()

            if not line or line.startswith("#"):
                continue

            parts = line.split()

            if len(parts) >= 2 and parts[0].lower() == "permitrootlogin":
                value = parts[1].lower()
    except OSError:
        return _result(
            "ssh_root_login",
            "SSH root login",
            "UNKNOWN",
            "INFO",
            "Unable to read SSH server configuration.",
            "Review /etc/ssh/sshd_config manually.",
        )

    if value is None:
        return _result(
            "ssh_root_login",
            "SSH root login",
            "WARNING",
            "MEDIUM",
            "PermitRootLogin is not explicitly configured.",
            "Explicitly disable direct root SSH login where appropriate.",
        )

    if value in {"no", "prohibit-password", "without-password"}:
        return _result(
            "ssh_root_login",
            "SSH root login",
            "PASS",
            "LOW",
            f"PermitRootLogin is configured as {value}.",
            "Keep direct root SSH access restricted.",
        )

    return _result(
        "ssh_root_login",
        "SSH root login",
        "FAIL",
        "HIGH",
        f"PermitRootLogin is configured as {value}.",
        "Disable direct root SSH login where operationally possible.",
    )


def _check_password_authentication() -> dict:
    path = Path("/etc/ssh/sshd_config")

    if not path.exists():
        return _result(
            "ssh_password_authentication",
            "SSH password authentication",
            "UNKNOWN",
            "INFO",
            "OpenSSH server configuration was not found.",
            "Review SSH authentication configuration manually.",
        )

    value = None

    try:
        for raw in path.read_text(
            encoding="utf-8",
            errors="ignore",
        ).splitlines():
            line = raw.strip()

            if not line or line.startswith("#"):
                continue

            parts = line.split()

            if len(parts) >= 2 and parts[0].lower() == "passwordauthentication":
                value = parts[1].lower()
    except OSError:
        return _result(
            "ssh_password_authentication",
            "SSH password authentication",
            "UNKNOWN",
            "INFO",
            "Unable to read SSH server configuration.",
            "Review SSH authentication configuration manually.",
        )

    if value == "no":
        return _result(
            "ssh_password_authentication",
            "SSH password authentication",
            "PASS",
            "LOW",
            "PasswordAuthentication is disabled.",
            "Continue using strong key-based authentication.",
        )

    if value == "yes":
        return _result(
            "ssh_password_authentication",
            "SSH password authentication",
            "WARNING",
            "MEDIUM",
            "PasswordAuthentication is enabled.",
            "Consider SSH keys and disabling password authentication where appropriate.",
        )

    return _result(
        "ssh_password_authentication",
        "SSH password authentication",
        "UNKNOWN",
        "INFO",
        "PasswordAuthentication is not explicitly configured.",
        "Review the effective SSH configuration.",
    )


def _check_firewall() -> dict:
    if shutil.which("ufw"):
        code, output = _run(["ufw", "status"])

        if code == 0:
            first = output.splitlines()[0].lower() if output else ""

            if "active" in first:
                return _result(
                    "firewall",
                    "Firewall status",
                    "PASS",
                    "LOW",
                    "UFW reports an active firewall.",
                    "Keep firewall rules minimal and reviewed.",
                )

            if "inactive" in first:
                return _result(
                    "firewall",
                    "Firewall status",
                    "FAIL",
                    "HIGH",
                    "UFW is installed but inactive.",
                    "Enable an appropriate host firewall.",
                )

    if shutil.which("nft"):
        code, output = _run(["nft", "list", "ruleset"])

        if code == 0 and output:
            return _result(
                "firewall",
                "Firewall status",
                "PASS",
                "LOW",
                "An nftables ruleset is present.",
                "Keep firewall rules reviewed and least-privilege.",
            )

    return _result(
        "firewall",
        "Firewall status",
        "WARNING",
        "HIGH",
        "No active host firewall could be confirmed.",
        "Configure an appropriate host firewall.",
    )


def _check_ssh_permissions() -> dict:
    path = Path("/etc/ssh/sshd_config")

    if not path.exists():
        return _result(
            "ssh_config_permissions",
            "SSH configuration permissions",
            "UNKNOWN",
            "INFO",
            "OpenSSH server configuration was not found.",
            "Review SSH configuration permissions manually.",
        )

    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return _result(
            "ssh_config_permissions",
            "SSH configuration permissions",
            "UNKNOWN",
            "INFO",
            "Unable to inspect SSH configuration permissions.",
            "Review /etc/ssh/sshd_config permissions.",
        )

    if mode & stat.S_IWOTH:
        return _result(
            "ssh_config_permissions",
            "SSH configuration permissions",
            "FAIL",
            "HIGH",
            f"SSH configuration is world-writable: {oct(mode)}.",
            "Remove world-write permissions from sshd_config.",
        )

    return _result(
        "ssh_config_permissions",
        "SSH configuration permissions",
        "PASS",
        "LOW",
        f"SSH configuration is not world-writable: {oct(mode)}.",
        "Keep SSH configuration protected from unprivileged modification.",
    )


def _check_ssh_service() -> dict:
    if not shutil.which("systemctl"):
        return _result(
            "ssh_service",
            "SSH service",
            "UNKNOWN",
            "INFO",
            "systemctl is not available.",
            "Review SSH service state manually.",
        )

    code, output = _run(["systemctl", "is-active", "ssh"])

    if code == 0 and output == "active":
        return _result(
            "ssh_service",
            "SSH service",
            "WARNING",
            "MEDIUM",
            "SSH service is currently active.",
            "Keep SSH enabled only when remote access is required.",
        )

    return _result(
        "ssh_service",
        "SSH service",
        "PASS",
        "LOW",
        "SSH service does not appear to be active.",
        "Keep unused network services disabled.",
    )


def run_hardening_audit() -> dict:
    """Run read-only Linux security hardening checks."""
    checks = [
        _check_ssh_root_login(),
        _check_password_authentication(),
        _check_firewall(),
        _check_ssh_permissions(),
        _check_ssh_service(),
    ]

    counts = {
        "PASS": sum(c["status"] == "PASS" for c in checks),
        "WARNING": sum(c["status"] == "WARNING" for c in checks),
        "FAIL": sum(c["status"] == "FAIL" for c in checks),
        "UNKNOWN": sum(c["status"] == "UNKNOWN" for c in checks),
    }

    if counts["FAIL"]:
        status = "FAIL"
    elif counts["WARNING"]:
        status = "WARNING"
    elif counts["UNKNOWN"]:
        status = "PARTIAL"
    else:
        status = "PASS"

    total = len(checks)

    score = round(
        (
            counts["PASS"] + (counts["UNKNOWN"] * 0.5)
        ) / total * 100
    ) if total else 0

    return {
        "tool": "TraceNox",
        "module": "Linux Security Hardening Auditor",
        "status": status,
        "security_score": score,
        "checks": checks,
        "summary": {
            "total": total,
            **counts,
        },
    }
