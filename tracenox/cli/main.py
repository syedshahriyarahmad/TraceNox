import argparse

from tracenox.analyzer.pipeline import analyze_log_file
from tracenox.reporting.text_report import generate_text_report


def main():
    parser = argparse.ArgumentParser(
        description="TraceNox — Evidence-Driven Cybersecurity Investigation Toolkit"
    )

    parser.add_argument(
        "log_file",
        help="Path to the SSH authentication log file",
    )

    args = parser.parse_args()

    try:
        result = analyze_log_file(args.log_file)
        report = generate_text_report(result)
        print(report)

    except FileNotFoundError:
        print(f"Error: log file not found: {args.log_file}")
    except Exception as error:
        print(f"Error: {error}")


if __name__ == "__main__":
    main()
