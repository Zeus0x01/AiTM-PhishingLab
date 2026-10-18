#!/usr/bin/env python3
"""Write all dataset artifact files (emails, web, JSON, JSONL, CSV)."""
from __future__ import annotations

import json
import os

from build import (ROOT, CASE_ID, DS_VERSION, build_email_1, build_email_2,
                   build_email_3, build_redirect_hop_1, build_redirect_hop_2,
                   build_page_source_js, build_login_page, build_saved_page,
                   build_device_code_page, build_signins, build_identity_audit,
                   build_mailbox_audit, build_alerts,
                   build_connection_events, build_incident_events, w)


def write_artifacts():
    # emails
    w("mail/eml/email-01-aitm-lure.eml", build_email_1())
    w("mail/eml/email-02-device-code.eml", build_email_2())
    w("mail/eml/email-03-legitimate-review.eml", build_email_3())
    # web
    w("artifacts/web/redirect-hop-01.txt", build_redirect_hop_1())
    w("artifacts/web/redirect-hop-02.txt", build_redirect_hop_2())
    w("artifacts/web/login-page.html", build_login_page())
    w("artifacts/web/saved-page.html", build_saved_page())
    w("artifacts/web/page-source.js", build_page_source_js())
    w("artifacts/web/device-code-page.html", build_device_code_page())
    # identity / logs / network
    w("artifacts/identity/signins.json",
      json.dumps(build_signins(), indent=2) + "\n")
    w("artifacts/identity/identity-audit.json",
      json.dumps(build_identity_audit(), indent=2) + "\n")
    w("artifacts/logs/alerts.json",
      json.dumps(build_alerts(), indent=2) + "\n")
    w("artifacts/logs/mailbox-audit.json",
      json.dumps(build_mailbox_audit(), indent=2) + "\n")
    w("artifacts/network/connection-events.json",
      json.dumps(build_connection_events(), indent=2) + "\n")
    rows = build_incident_events()
    w("artifacts/logs/incident-events.jsonl",
      "".join(json.dumps(r) + "\n" for r in rows))
    # generated CSV index (same rows, no added facts)
    csv_lines = ["timestamp_utc,event_id,source_dataset,category,actor"]
    for r in sorted(rows, key=lambda x: x["timestamp_utc"]):
        csv_lines.append(",".join([
            r["timestamp_utc"], r["source_event_id"], r["source_dataset"],
            r["category"], r["actor"] or "",
        ]))
    w("artifacts/logs/incident-timeline.csv", "\n".join(csv_lines) + "\n")
    return rows


if __name__ == "__main__":
    rows = write_artifacts()
    print(f"artifacts written: incident rows={len(rows)}")


def main():
    return write_artifacts()
