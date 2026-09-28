import argparse
import sys

from tracenox.analyzer.pipeline import analyze_log_file
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
        help="Path to the SSH authentication log file",
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

    try:
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
        print(f"File error: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
