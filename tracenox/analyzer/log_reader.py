from pathlib import Path
import subprocess


def read_log_file(file_path: str) -> list[str]:
    """Read a log file and return its lines."""
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    if not path.is_file():
        raise ValueError(f"Not a file: {file_path}")

    return path.read_text(errors="replace").splitlines()


def read_journal_lines(
    unit: str = "ssh",
    since: str = "today",
) -> list[str]:
    """Read real systemd journal entries using journalctl."""
    if not unit or unit.startswith("-"):
        raise ValueError("Invalid systemd unit name.")

    if not since or since.startswith("-"):
        raise ValueError("Invalid journal time range.")

    command = [
        "sudo", "journalctl",
        "-u", unit,
        "--since", since,
        "--no-pager",
        "-o", "short",
    ]

    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    if completed.returncode != 0:
        message = completed.stderr.strip() or "journalctl failed."
        raise ValueError(f"Unable to read system journal: {message}")

    return completed.stdout.splitlines()
