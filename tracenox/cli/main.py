import argparse
import sys

from tracenox.analyzer.integrity import (
    create_file_integrity_baseline,
    scan_file_integrity,
    verify_file_sha256,
)
from tracenox.analyzer.pipeline import analyze_journal, analyze_log_file
from tracenox.reporting.html_report import save_html_report
from tracenox.reporting.json_report import save_json_report
from tracenox.reporting.text_report import generate_text_report
from tracenox.hardening import run_hardening_audit


def main():
    parser = argparse.ArgumentParser(
        description=(
            "TraceNox — Evidence-Driven Cybersecurity "
            "Investigation Toolkit"
        )
    )

    parser.add_argument(
        "log_file",
        nargs="?",
        help="Path to an SSH authentication log file",
    )
    parser.add_argument(
        "--journal",
        action="store_true",
        help="Analyze systemd journal entries instead of a log file",
    )
    parser.add_argument(
        "--unit",
        default="ssh",
        help="Systemd unit to inspect when using --journal (default: ssh)",
    )
    parser.add_argument(
        "--since",
        default="today",
        help="Journal time range, e.g. today, yesterday, or '2 hours ago'",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        metavar="OUTPUT",
        help="Save investigation results as JSON",
    )
    parser.add_argument(
        "--html",
        dest="html_output",
        metavar="OUTPUT",
        help="Save an HTML investigation report",
    )
    parser.add_argument(
        "--ip-reputation",
        action="store_true",
        help=(
            "Explicitly query AbuseIPDB for public source IPs. "
            "Requires ABUSEIPDB_API_KEY."
        ),
    )
    parser.add_argument(
        "--hardening",
        action="store_true",
        help="Run read-only Linux security hardening checks",
    )

    parser.add_argument(
        "--verify-hash",
        metavar="FILE",
        help="Verify a file against an expected SHA-256 hash",
    )
    parser.add_argument(
        "--expected-sha256",
        metavar="HASH",
        help="Expected 64-character SHA-256 hash for --verify-hash",
    )
    parser.add_argument(
        "--fim-create-baseline",
        metavar="DIRECTORY",
        help="Create a SHA-256 file integrity baseline for a directory",
    )
    parser.add_argument(
        "--fim-baseline",
        metavar="BASELINE",
        help="Path to an existing TraceNox FIM baseline JSON file",
    )
    parser.add_argument(
        "--fim-scan",
        metavar="DIRECTORY",
        help="Scan a directory against a TraceNox FIM baseline",
    )
    parser.add_argument(
        "--fim-output",
        metavar="OUTPUT",
        help="Save FIM results as JSON",
    )

    args = parser.parse_args()

    if args.verify_hash:
        if not args.expected_sha256:
            parser.error("--verify-hash requires --expected-sha256.")

        if (
            args.log_file
            or args.journal
            or args.json_output
            or args.html_output
            or args.ip_reputation
            or args.fim_create_baseline
            or args.fim_baseline
            or args.fim_scan
            or args.fim_output
        ):
            parser.error(
                "--verify-hash is a standalone operation; do not combine it "
                "with log analysis, FIM, or report output options."
            )

        try:
            matches, actual_hash = verify_file_sha256(
                args.verify_hash,
                args.expected_sha256,
            )
            print(f"File              : {args.verify_hash}")
            print(f"Calculated SHA-256: {actual_hash}")

            if matches:
                print("Verification      : MATCH")
                print("Result            : File bytes match the expected SHA-256.")
            else:
                print("Verification      : MISMATCH")
                print(
                    "Result            : File bytes do not match "
                    "the expected SHA-256."
                )
                sys.exit(1)

            return
        except (FileNotFoundError, ValueError) as error:
            print(f"Error: {error}", file=sys.stderr)
            sys.exit(1)
        except OSError as error:
            print(f"File or system error: {error}", file=sys.stderr)
            sys.exit(1)

    if args.expected_sha256:
        parser.error("--expected-sha256 can only be used with --verify-hash.")

    if args.hardening:
        forbidden = (
            args.log_file
            or args.journal
            or args.json_output
            or args.html_output
            or args.ip_reputation
            or args.verify_hash
            or args.expected_sha256
            or args.fim_create_baseline
            or args.fim_baseline
            or args.fim_scan
            or args.fim_output
        )

        if forbidden:
            parser.error("--hardening is a standalone operation.")

        result = run_hardening_audit()

        print("TraceNox Linux Security Hardening Audit")
        print("---------------------------------------")
        print(f"Status         : {result['status']}")
        print(f"Security score : {result['security_score']}/100")

        summary = result["summary"]

        print(
            f"Checks         : {summary['total']} | "
            f"PASS={summary['PASS']} "
            f"WARNING={summary['WARNING']} "
            f"FAIL={summary['FAIL']} "
            f"UNKNOWN={summary['UNKNOWN']}"
        )

        for check in result["checks"]:
            print()
            print(f"[{check['status']}] {check['title']}")
            print(f"  Detail         : {check['detail']}")
            print(f"  Recommendation : {check['recommendation']}")

        return

    if args.fim_create_baseline:
        if (
            args.log_file
            or args.journal
            or args.json_output
            or args.html_output
            or args.ip_reputation
            or args.fim_baseline
            or args.fim_scan
        ):
            parser.error(
                "--fim-create-baseline is a standalone FIM operation."
            )

        try:
            output = args.fim_output or "tracenox-fim-baseline.json"
            baseline = create_file_integrity_baseline(
                args.fim_create_baseline,
                output,
            )

            print(f"FIM baseline created: {output}")
            print(f"Root directory      : {baseline['root_directory']}")
            print(f"Files recorded      : {baseline['file_count']}")
            print(f"Hash algorithm      : {baseline['hash_algorithm']}")
            return
        except (FileNotFoundError, ValueError) as error:
            print(f"Error: {error}", file=sys.stderr)
            sys.exit(1)
        except OSError as error:
            print(f"File or system error: {error}", file=sys.stderr)
            sys.exit(1)

    if args.fim_scan:
        if not args.fim_baseline:
            parser.error("--fim-scan requires --fim-baseline.")

        if (
            args.log_file
            or args.journal
            or args.json_output
            or args.html_output
            or args.ip_reputation
            or args.fim_create_baseline
        ):
            parser.error("--fim-scan is a standalone FIM operation.")

        try:
            result = scan_file_integrity(
                args.fim_scan,
                args.fim_baseline,
            )

            summary = result["summary"]

            print("TraceNox File Integrity Monitoring")
            print("----------------------------------")
            print(f"Root directory : {result['root_directory']}")
            print(f"Baseline       : {result['baseline_file']}")
            print(f"Status         : {result['status']}")
            print(f"Unchanged      : {summary['unchanged']}")
            print(f"Modified       : {summary['modified']}")
            print(f"Added          : {summary['added']}")
            print(f"Deleted        : {summary['deleted']}")

            for category in ("modified", "added", "deleted"):
                paths = result["findings"][category]
                if paths:
                    print(f"\n{category.upper()}")
                    print("-" * len(category))
                    for path in paths:
                        print(f"- {path}")

            if args.fim_output:
                save_json_report(result, args.fim_output)
                print(f"\nFIM JSON report saved to: {args.fim_output}")

            if result["status"] != "CLEAN":
                sys.exit(1)

            return
        except (FileNotFoundError, ValueError) as error:
            print(f"Error: {error}", file=sys.stderr)
            sys.exit(1)
        except OSError as error:
            print(f"File or system error: {error}", file=sys.stderr)
            sys.exit(1)

    if args.fim_baseline or args.fim_output:
        parser.error(
            "--fim-baseline and --fim-output can only be used with "
            "--fim-scan or --fim-create-baseline."
        )

    if args.journal and args.log_file:
        parser.error("Use either --journal or a log_file, not both.")

    if not args.journal and not args.log_file:
        parser.error(
            "Provide a log_file, use --journal, --verify-hash, "
            "--fim-create-baseline, or --fim-scan."
        )

    try:
        if args.journal:
            result = analyze_journal(
                unit=args.unit,
                since=args.since,
                enable_ip_reputation=args.ip_reputation,
            )
        else:
            result = analyze_log_file(
                args.log_file,
                enable_ip_reputation=args.ip_reputation,
            )

        print(generate_text_report(result))

        if result.get("analysis_warning"):
            print(
                "\nANALYSIS WARNING: "
                + result["analysis_warning"],
                file=sys.stderr,
            )

        if args.ip_reputation:
            print("\nIP Reputation Results")
            print("---------------------")
            for address, reputation in result["ip_reputation"].items():
                print(
                    f"{address}: {reputation.get('status', 'unknown')}"
                )
                if reputation.get("abuse_confidence_score") is not None:
                    print(
                        "  Abuse confidence score: "
                        f"{reputation['abuse_confidence_score']}"
                    )
                if reputation.get("reason"):
                    print(f"  Note: {reputation['reason']}")

        if args.json_output:
            save_json_report(result, args.json_output)
            print(f"\nJSON report saved to: {args.json_output}")

        if args.html_output:
            save_html_report(result, args.html_output)
            print(f"HTML report saved to: {args.html_output}")

    except (FileNotFoundError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
    except OSError as error:
        print(f"File or system error: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
