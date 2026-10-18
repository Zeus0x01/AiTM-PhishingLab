#!/usr/bin/env python3
"""Package: SHA256SUMS manifest + trainee-facing ZIP bundle.

Trainee payload (no instructor pack, no sources, no deploy/portal bits):
  Zeus0x01-AiTM-Investigation/
    README.md  SAFETY.md  short-answer-questions.md  SHA256SUMS
    mail/eml/*.eml
    artifacts/{web,identity,logs,network,documentation}/
    tools/optional-import-examples/siem-imports.md
"""
from __future__ import annotations

import hashlib
import io
import os
import zipfile

from build import ROOT, DS_VERSION

BUNDLE_NAME = "Zeus0x01-AiTM-Investigation"
ZIP_REL = os.path.join("downloads", BUNDLE_NAME + ".zip")

INCLUDE = [
    "README.md",
    "SAFETY.md",
    "short-answer-questions.md",
    "SHA256SUMS",
    "mail/eml/email-01-aitm-lure.eml",
    "mail/eml/email-02-device-code.eml",
    "mail/eml/email-03-legitimate-review.eml",
    "artifacts/web/redirect-hop-01.txt",
    "artifacts/web/redirect-hop-02.txt",
    "artifacts/web/login-page.html",
    "artifacts/web/saved-page.html",
    "artifacts/web/page-source.js",
    "artifacts/web/device-code-page.html",
    "artifacts/web/offline-checklist.html",
    "artifacts/identity/signins.json",
    "artifacts/identity/identity-audit.json",
    "artifacts/logs/alerts.json",
    "artifacts/logs/mailbox-audit.json",
    "artifacts/logs/incident-events.jsonl",
    "artifacts/logs/incident-timeline.csv",
    "artifacts/network/connection-events.json",
    "artifacts/documentation/field-reference.md",
    "artifacts/documentation/evidence-inventory.md",
    "tools/optional-import-examples/siem-imports.md",
]

EXCLUDE_MARKERS = ("instructor", "sources", "deploy", "downloads",
                   "api", "public", "vercel.json")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest():
    hashes = {}
    for rel in INCLUDE:
        if rel == "SHA256SUMS":
            continue
        hashes[rel] = sha256_file(os.path.join(ROOT, rel))
    lines = [f"{digest}  {rel}" for rel, digest in hashes.items()]
    content = "\n".join(sorted(lines)) + "\n"
    with open(os.path.join(ROOT, "SHA256SUMS"), "w", encoding="utf-8",
              newline="\n") as fh:
        fh.write(content)
    return hashes


def write_zip():
    zip_path = os.path.join(ROOT, ZIP_REL)
    os.makedirs(os.path.dirname(zip_path), exist_ok=True)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel in INCLUDE:
            src = os.path.join(ROOT, rel)
            if not os.path.exists(src):
                raise SystemExit(f"missing required file: {rel}")
            with open(src, "rb") as fh:
                data = fh.read()
            if rel.endswith(".eml") and b"\r\n" not in data:
                raise SystemExit(f".eml not CRLF: {rel}")
            if rel.endswith((".md", ".json", ".js", ".html", ".csv", ".jsonl",
                             ".txt")):
                norm = data.replace(b"\r\n", b"\n")
                if norm != data:
                    raise SystemExit(
                        f"file on disk not LF-normalized: {rel}")
                data = norm
            if rel.endswith(".eml") and data.replace(b"\r\n", b"\n") != data and data.count(b"\r\n") == 0:
                raise SystemExit(f".eml not CRLF: {rel}")
            zf.writestr(f"{BUNDLE_NAME}/{rel}", data)
    with open(zip_path, "wb") as fh:
        fh.write(buf.getvalue())
    return zip_path, hashlib.sha256(buf.getvalue()).hexdigest()


def write_integrity_note(zip_path, archive_hash):
    lines = [
        f"# Archive integrity - {BUNDLE_NAME}",
        "",
        f"Dataset version: {DS_VERSION}",
        "",
        "SHA-256 of the released archive:",
        "",
        f"`{archive_hash}`",
        "",
        "File-level hashes are inside the bundle (SHA256SUMS) and the same",
        "manifest ships at the repository root. Verify with:",
        "",
        "```",
        "sha256sum -c SHA256SUMS   # after extraction",
        "```",
        "",
    ]
    with open(os.path.join(ROOT, "downloads", "INTEGRITY.md"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))


def package(hashes=None):
    write_manifest()
    zip_path, archive_hash = write_zip()
    write_integrity_note(zip_path, archive_hash)
    print(f"packaged: {ZIP_REL} sha256={archive_hash}")
    return archive_hash
