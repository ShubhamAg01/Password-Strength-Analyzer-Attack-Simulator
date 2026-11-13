import sys
import argparse
import os


def main():
    parser = argparse.ArgumentParser(description="Password Strength Analyzer & Attack Simulator")
    parser.add_argument("--cli", action="store_true", help="Run CLI interface")
    parser.add_argument("--web", action="store_true", help="Start web dashboard on port 5050")
    parser.add_argument("--benchmarks", action="store_true", help="Run benchmark suite")
    parser.add_argument("--report", action="store_true", help="Generate project report")

    args = parser.parse_args()

    if not os.path.exists("wordlists/common_passwords.txt") or not os.path.exists("wordlists/test_hashes.json"):
        from src.wordlist_generator import generate_curated_wordlist, generate_test_target_hashes
        generate_curated_wordlist()
        generate_test_target_hashes()

    if args.benchmarks:
        from src.generate_benchmarks import run_and_save_all_benchmarks
        run_and_save_all_benchmarks()
        return

    if args.report:
        from report.generate_report import build_full_report
        build_full_report()
        return

    if args.cli:
        from src.cli import run_cli
        run_cli()
        return

    if args.web:
        from src.web_app import run_web_server
        run_web_server()
        return

    print("Password Security Workbench")
    print("---------------------------")
    print("1. Web Dashboard")
    print("2. Terminal CLI")
    print("3. Run Benchmarks")
    print("4. Generate Report")
    print("5. Exit")

    choice = input("\nChoice (1-5) [1]: ").strip() or "1"
    if choice == "1":
        from src.web_app import run_web_server
        run_web_server()
    elif choice == "2":
        from src.cli import run_cli
        run_cli()
    elif choice == "3":
        from src.generate_benchmarks import run_and_save_all_benchmarks
        run_and_save_all_benchmarks()
    elif choice == "4":
        from report.generate_report import build_full_report
        build_full_report()


if __name__ == "__main__":
    main()
