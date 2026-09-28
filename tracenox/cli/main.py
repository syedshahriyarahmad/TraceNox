import argparse
import sys

from tracenox.analyzer.pipeline import analyze_journal, analyze_log_file
from tracenox.reporting.html_report import save_html_report
from tracenox.reporting.json_report import save_json_report
from tracenox.reporting.text_report import generate_text_report


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

    args = parser.parse_args()

    if args.journal and args.log_file:
        parser.error("Use either --journal or a log_file, not both.")

    if not args.journal and not args.log_file:
        parser.error("Provide a log_file or use --journal.")

    try:
        if args.journal:
            result = analyze_journal(unit=args.unit, since=args.since)
        else:
            result = analyze_log_file(args.log_file)

        print(generate_text_report(result))

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
