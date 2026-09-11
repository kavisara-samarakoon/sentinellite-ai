"""A bundled, in-memory fixture demo with no host observation or log-file input."""

from pathlib import Path

from sentinellite.collectors.auth import parse_auth_line
from sentinellite.pipeline.auth_scan import AuthScanSummary, report_auth_events
from sentinellite.scoring.risk import ScoredAlert

# Synthetic records only; addresses are documentation examples, never connection targets.
DEMO_AUTH_LINES = (
    (
        "Sep 11 12:00:01 synthetic-demo sshd[1001]: Failed password for invalid user "
        "demo-user from 192.0.2.10 port 50001 ssh2"
    ),
    (
        "Sep 11 12:00:02 synthetic-demo sshd[1002]: Accepted password for "
        "demo-user from 192.0.2.20 port 50002 ssh2"
    ),
    (
        "Sep 11 12:00:03 synthetic-demo sudo: demo-user : TTY=pts/0 ; "
        "PWD=/demo ; USER=root ; COMMAND=/usr/bin/id"
    ),
)


def run_demo(
    output_dir: str | Path = "reports",
    *,
    include_explanations: bool = False,
) -> tuple[AuthScanSummary, list[ScoredAlert]]:
    """Write a normal report from fixed synthetic records and built-in rules."""
    events = [event for line in DEMO_AUTH_LINES if (event := parse_auth_line(line)) is not None]
    return report_auth_events(
        events,
        log_path="bundled synthetic demo (in memory)",
        output_dir=output_dir,
        include_explanations=include_explanations,
        host_id="synthetic-demo",
    )
