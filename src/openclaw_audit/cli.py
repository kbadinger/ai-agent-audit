"""Command-line interface for openclaw-audit."""

from __future__ import annotations

import argparse
import sys
import webbrowser

from .daemon import read_pid, write_pid, stop_daemon, daemonize, setup_logging
from .db import FindingsDB
from .engine import build_default_engine
from .report import ReportGenerator


def cmd_start(args: argparse.Namespace) -> None:
    """Start the audit daemon."""
    pid = read_pid()
    if pid is not None:
        print(f"Daemon already running (PID {pid}).")
        return

    print("Starting openclaw-audit daemon...")
    sys.stdout.flush()
    sys.stderr.flush()
    daemonize()

    # Now running as daemon (detached, stdio -> /dev/null)
    setup_logging()
    write_pid()

    import os
    import signal
    import time

    engine = build_default_engine()
    stop_event = False

    def handle_signal(signum, frame):
        nonlocal stop_event
        stop_event = True
        engine.stop()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    engine.start()

    while not stop_event:
        time.sleep(1)


def cmd_stop(args: argparse.Namespace) -> None:
    """Stop the audit daemon."""
    if stop_daemon():
        print("Daemon stopped.")
    else:
        print("Daemon is not running.")


def cmd_status(args: argparse.Namespace) -> None:
    """Show daemon status."""
    pid = read_pid()
    if pid is not None:
        print(f"Status: running (PID {pid})")
    else:
        print("Status: stopped")

    try:
        db = FindingsDB()
        findings = db.get_active_findings()
        critical = sum(1 for f in findings if f["severity"] == 2)
        warning = sum(1 for f in findings if f["severity"] == 1)
        info = sum(1 for f in findings if f["severity"] == 0)
        print(f"Active findings: {len(findings)} ({critical} critical, {warning} warning, {info} info)")
        if findings:
            from datetime import datetime
            last_seen = max(f["last_seen"] for f in findings)
            print(f"Last finding: {datetime.fromtimestamp(last_seen).strftime('%Y-%m-%d %H:%M:%S')}")
        db.close()
    except Exception:
        print("No audit data available yet.")


def cmd_sweep(args: argparse.Namespace) -> None:
    """Run all sweeps in the foreground."""
    setup_logging(foreground=True)
    print("Running security sweeps...")

    db = FindingsDB()
    engine = build_default_engine(db=db)
    results = engine.run_all_sweeps()

    total = 0
    for result in results:
        count = len(result.findings)
        total += count
        if count > 0:
            print(f"  {result.module_name}: {count} finding(s)")

    if total == 0:
        print("No findings detected.")
    else:
        print(f"\nTotal: {total} finding(s)")

    db.close()


def cmd_fix(args: argparse.Namespace) -> None:
    """Run auto-remediation."""
    from .remediate import RemediationEngine

    engine = RemediationEngine(dry_run=args.dry_run)
    actions = engine.run_all()

    if not actions:
        print("No remediation actions needed.")
        return

    prefix = "DRY-RUN" if args.dry_run else "APPLIED"
    for action in actions:
        status = "APPLIED" if action["applied"] else ("DRY-RUN" if args.dry_run else "FAILED")
        print(f"  [{status}] {action['action']}: {action['detail']}")

    print(f"\nTotal: {len(actions)} action(s) ({prefix})")


def cmd_update_ioc(args: argparse.Namespace) -> None:
    """Update IOC database from external feeds."""
    from .ioc_updater import IOCUpdater

    updater = IOCUpdater()

    if args.file:
        stats = updater.update_from_file(args.file)
    elif args.url:
        stats = updater.update_from_url(args.url)
    else:
        # Show current stats
        s = updater.stats()
        print("IOC Database:")
        for key, count in s.items():
            print(f"  {key}: {count}")
        return

    if "error" in stats:
        print(f"Error: {stats['error']}", file=sys.stderr)
        sys.exit(1)

    print("IOC update complete:")
    for key, value in stats.items():
        print(f"  {key}: {value}")


def cmd_triage(args: argparse.Namespace) -> None:
    """Triage findings — list, confirm, dismiss, or mark as false positive."""
    from .learner import PrecisionTracker

    db = FindingsDB()

    if args.finding_id is None:
        # List mode: show triageable findings
        findings = db.get_triageable()
        if not findings:
            print("No active findings to triage.")
            db.close()
            return

        severity_labels = {0: "INFO", 1: "WARN", 2: "CRIT"}
        print(f"{'ID':>5}  {'Sev':5}  {'Conf':5}  {'Status':10}  {'Title'}")
        print("-" * 72)
        for f in findings:
            sev = severity_labels.get(f["severity"], "?")
            conf = f"{f['confidence']:.2f}" if f["confidence"] is not None else "0.50"
            status = f["triage_status"] or "-"
            print(f"{f['id']:>5}  {sev:5}  {conf:5}  {status:10}  {f['title']}")
        db.close()
        return

    # Triage a specific finding
    status = None
    if args.confirm:
        status = "confirmed"
    elif args.fp:
        status = "false_positive"
    elif args.dismiss:
        status = "dismissed"
    else:
        print("Specify --confirm, --fp, or --dismiss.", file=sys.stderr)
        db.close()
        sys.exit(1)

    if db.triage(args.finding_id, status):
        # Refresh precision scores
        tracker = PrecisionTracker(db=db)
        tracker.refresh()
        print(f"Finding {args.finding_id} marked as '{status}'. Precision scores updated.")
    else:
        print(f"Finding {args.finding_id} not found.", file=sys.stderr)
        db.close()
        sys.exit(1)

    db.close()


def cmd_export(args: argparse.Namespace) -> None:
    """Export findings in SARIF, JSONL, or CSV format."""
    from .export import export_findings

    db = FindingsDB()
    try:
        content = export_findings(db, fmt=args.format, output_path=args.output)
        if not args.output:
            sys.stdout.write(content)
            if content and not content.endswith("\n"):
                sys.stdout.write("\n")
        else:
            print(f"Exported to: {args.output}")
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        db.close()


def cmd_report(args: argparse.Namespace) -> None:
    """Generate an HTML report."""
    try:
        gen = ReportGenerator()
        path = gen.generate()
        print(f"Report saved to: {path}")
        if args.open:
            webbrowser.open(f"file://{path}")
    except Exception as e:
        print(f"Error generating report: {e}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    """Entry point for openclaw-audit CLI."""
    parser = argparse.ArgumentParser(
        prog="openclaw-audit",
        description="Security audit daemon for OpenClaw installations",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("start", help="Start the audit daemon")
    sub.add_parser("stop", help="Stop the audit daemon")
    sub.add_parser("status", help="Show daemon status and finding summary")
    sub.add_parser("sweep", help="Run all security sweeps (foreground)")

    triage_parser = sub.add_parser("triage", help="Triage findings (confirm/fp/dismiss)")
    triage_parser.add_argument("finding_id", nargs="?", type=int, default=None, help="Finding ID to triage")
    triage_group = triage_parser.add_mutually_exclusive_group()
    triage_group.add_argument("--confirm", action="store_true", help="Mark as confirmed true positive")
    triage_group.add_argument("--fp", action="store_true", help="Mark as false positive")
    triage_group.add_argument("--dismiss", action="store_true", help="Dismiss (not relevant)")

    export_parser = sub.add_parser("export", help="Export findings (SARIF, JSONL, CSV)")
    export_parser.add_argument(
        "--format", "-f",
        choices=["sarif", "jsonl", "csv", "navigator", "stix", "stix-ioc", "sbom"],
        default="jsonl",
        help="Output format (default: jsonl)",
    )
    export_parser.add_argument(
        "--output", "-o", help="Output file path (default: stdout)",
    )

    report_parser = sub.add_parser("report", help="Generate an HTML report")
    report_parser.add_argument(
        "--open", action="store_true", help="Open report in browser"
    )

    fix_parser = sub.add_parser("fix", help="Auto-remediate security findings")
    fix_parser.add_argument(
        "--dry-run", action="store_true", help="Show what would be fixed without applying"
    )

    ioc_parser = sub.add_parser("update-ioc", help="Update IOC database")
    ioc_source = ioc_parser.add_mutually_exclusive_group()
    ioc_source.add_argument("--url", help="URL to fetch IOC JSON from")
    ioc_source.add_argument("--file", help="Local file path to load IOC JSON from")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    commands = {
        "start": cmd_start,
        "stop": cmd_stop,
        "status": cmd_status,
        "sweep": cmd_sweep,
        "triage": cmd_triage,
        "export": cmd_export,
        "report": cmd_report,
        "fix": cmd_fix,
        "update-ioc": cmd_update_ioc,
    }
    commands[args.command](args)
