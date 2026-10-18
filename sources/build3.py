#!/usr/bin/env python3
"""Part 3: question files, instructor pack, SIEM examples."""
from __future__ import annotations

import json
import os

from build import (ROOT, DS_VERSION, CASE_ID, QUESTIONS, flag_fragments,
                   canonical_flag, REAL_IOC_DEFANGED, IP_ATTACKER, w,
                   CORE_THRESH)

CORE_MAX = sum(q["points"] for q in QUESTIONS if q["category"] != "Bonus")
BONUS_MAX = sum(q["points"] for q in QUESTIONS if q["category"] == "Bonus")

# verifier answer types: str|dompair|msgid|enum (must match api/verify.js
# normalization variants). Pairs accept both orders; msgid accepts with or
# without angle brackets; enum accepts hyphen/space-insensitive matches.
ANSWER_TYPE = {
    3: "dompair", 4: "dompair", 6: "dompair", 9: "dompair", 11: "dompair",
    12: "dompair", 13: "dompair", 14: "dompair",
    8: "enum", 11: "dompair", 19: "enum", 24: "enum",
    20: "msgid",
}


def write_short_answer_questions():
    parts = [
        "# short-answer-questions.md — Zeus0x01 AiTM Phishing Investigation",
        "",
        "One line per question; every answer is short and exact (an IP, a domain,",
        "an ID, a timestamp, a path, a token, an enum value, or a",
        "comma-separated pair).",
        "No explanations. Case-insensitive unless a format says otherwise;",
        "leading/trailing spaces ignored. Every question names its evidence",
        "sources and its answer format. The README, SAFETY.md and the dataset",
        "documentation files carry the scenario narrative; this file is",
        "questions only.",
        "",
        f"Dataset v{DS_VERSION} · incident {CASE_ID} · 21 core + 5 bonus.",
        "Core questions are 1-21 (1 or 2 points, noted per question); bonuses",
        "are 22-26 (1 point each).",
        "",
        "## Core questions  (max 30 points, threshold 23)",
        "",
    ]
    for q in QUESTIONS:
        if q["category"] == "Bonus":
            continue
        parts.append(f"{q['id']}. {q['title']} {q['prompt']}")
        parts.append(f"Answer format: `{q['answer_format']}`  (evidence: "
                     + ", ".join(a.rsplit("/", 1)[-1]
                                 for a in q["artifacts"]) + ")")
        parts.append("")
    parts.append("## Bonus questions  (max 5 points)")
    parts.append("")
    for q in QUESTIONS:
        if q["category"] == "Bonus":
            parts.append(f"{q['id']}. {q['title']} {q['prompt']}")
            parts.append(f"Answer format: `{q['answer_format']}`  (evidence: "
                         + ", ".join(a.rsplit("/", 1)[-1]
                                     for a in q["artifacts"]) + ")")
            parts.append("")
    parts.append("## Final flag")
    parts.append("")
    parts.append("Four flag fragments fall out of four independent evidence")
    parts.append("categories: (F1) email/header evidence, (F2) static web")
    parts.append("artifact, (F3) identity/audit-log correlation, (F4) published")
    parts.append("threat-intelligence reference. F3 and F4 correspond to core")
    parts.append("questions 12 and 15; F1 and F2 are bonus decodes (questions")
    parts.append("22 and 23).")
    parts.append("Once your core score clears the threshold, submit all four")
    parts.append("fragment codes on the lab portal to release the final flag.")
    w("short-answer-questions.md", "\n".join(parts) + "\n")


def write_question_bank():
    bank = {
        "lab": "Zeus0x01-AiTM-Investigation",
        "dataset_version": DS_VERSION,
        "incident_ref": CASE_ID,
        "core_threshold_points": CORE_THRESH,
        "questions": [],
        "flag_fragments": [],
        "canonical_flag": canonical_flag(),
    }
    for q in QUESTIONS:
        bank["questions"].append({
            "id": q["id"],
            "title": q["title"],
            "category": q["category"],
            "type": ANSWER_TYPE.get(q["id"], "str"),
            "prompt": q["prompt"],
            "answer_format": q["answer_format"],
            "points": q["points"],
            "accepted": q["accepted"],
            "artifacts": q["artifacts"],
        })
    for fid, label, value, meaning, source, linked_q in flag_fragments():
        bank["flag_fragments"].append({
            "id": fid, "label": label, "value": value, "meaning": meaning,
            "source": source, "linked_question": linked_q,
        })
    w(os.path.join("instructor", "question-bank.json"),
      json.dumps(bank, indent=2) + "\n")


def write_answer_key():
    lines = [
        "# Instructor answer key — Zeus0x01 AiTM Phishing Investigation",
        "",
        f"Dataset v{DS_VERSION} · fictional incident {CASE_ID}.",
        "Canonical flag (server-side / platform-configured; never shown to",
        "trainees outside this instructor pack):",
        "",
        "```",
        canonical_flag(),
        "```",
        "",
        f"Scoring: core max = {CORE_MAX} points (passing threshold {CORE_THRESH});"
        f" bonus max = {BONUS_MAX} points.",
        "",
    ]
    for q in QUESTIONS:
        accepted = " | ".join("`" + a + "`" for a in q["accepted"])
        lines += [
            f"## Q{q['id']} {q['title']}",
            f"*Category:* {q['category']} · *Points:* {q['points']}",
            f"*Answer format:* {q['answer_format']}",
            f"*Expected answer:* {accepted}",
            f"*Evidence artifacts:* {', '.join(q['artifacts'])}",
            "*Grading rules:* trim, lowercase, collapse internal whitespace;",
            "  split multi-part answers on the literal comma (on the trimmed",
            "  string) and compare pairwise with BOTH orders accepted;",
            "  message-ID answers accept with or without angle brackets;",
            "  enum answers must match the fixed list exactly (hyphen/space",
            "  variants allowed); numbers compare as normalized strings;",
            "  no partial credit.",
            "",
        ]
    lines.append("## Flag fragments")
    lines.append("")
    for fid, label, value, meaning, source, linked_q in flag_fragments():
        lines.append(f"* **{fid} ({label})** = `{value}` — {meaning}; recovered "
                     f"via {linked_q} from {source}.")
    lines += [
        "",
        "## Reproducibility notes",
        "",
        "* Every event ID quoted here exists in the shipped datasets; the",
        "  build script (`sources/build.py`) regenerates all artifacts",
        "  deterministically and re-derives every accepted answer from the",
        "  generated data (see `sources/validate.py`).",
        "* Threat-intel answers (Q14, Q15, Q16) cite the reports named in the",
        "  question text:",
        f"  - Sekoia TDR, 2025-03-25 — `{REAL_IOC_DEFANGED}` appears in the",
        "    Tycoon 2FA IOC table (family: Tycoon 2FA).",
        "  - Darktrace, 2025-04-29 — maps the campaign to the MITRE ATT&CK",
        "    technique \"Steal Web Session Cookie\" (T1539).",
        "  - Microsoft Threat Intelligence, 2025-02-13 — \"Storm-2372 conducts",
        "    device code phishing campaign\" (actor: Storm-2372).",
    ]
    w(os.path.join("instructor", "answer-key.md"), "\n".join(lines) + "\n")


def write_scoring_rubric():
    txt = (
        "# Scoring rubric — Zeus0x01 AiTM Phishing Investigation\n"
        "\n"
        f"Dataset v{DS_VERSION}.\n"
        "\n"
        "* **Core scoring** — 21 core questions; twelve are 1 point, nine are\n"
        "  2 points (multi-artifact correlation). Maximum core score =\n"
        f"  {CORE_MAX} points.\n"
        f"* **Bonus scoring** — 5 bonus questions, 1 point each; max {BONUS_MAX}.\n"
        f"* **Passing threshold** — {CORE_THRESH} of {CORE_MAX} core points"
        " (~77%).\n"
        "  The final flag is released on the verification portal only once this\n"
        "  threshold is met AND all four flag fragments verify.\n"
        "* **Flag fragments** — F1 = email/header evidence, F2 = static web\n"
        "  artifact, F3 = identity/audit-log correlation, F4 = published\n"
        "  threat-intelligence reference. Each fragment is linked to a verified\n"
        "  question (see answer key). No single artifact or question reveals\n"
        "  the whole flag; no grader accepts partial fragments.\n"
        "* **Normalization** (applied uniformly by any checker):\n"
        "  1. Trim surrounding whitespace.\n"
        "  2. Lowercase.\n"
        "  3. Collapse internal whitespace runs to a single space.\n"
        "  4. Multi-value answers: split on the literal comma, trim each part,\n"
        "     and accept both pair orders (`a,b` == `b,a`).\n"
        "  5. Message-ID answers accept with or without angle brackets.\n"
        "  6. Enum answers must match the fixed list exactly (hyphen/space\n"
        "     variants allowed, e.g. `console-only` == `CONSOLE ONLY`).\n"
        "  7. Numeric answers compare as normalized strings.\n"
        "* **Partial credit** — none; every question is correct or incorrect.\n"
        "* **Determinism** — grading is a pure function of the submitted\n"
        "  string plus the normalization rules above; no subjective review.\n"
        "\n"
        "## Platform import notes (HTB / CyberDefenders / CTFd)\n"
        "\n"
        "* Use `instructor/question-bank.json` as the source of truth for\n"
        "  question text, points, accepted answers and flag fragments.\n"
        "* Configure the canonical flag from `answer-key.md`; it must never be\n"
        "  embedded in trainee-facing artifacts (evidence ZIP, offline page).\n"
        "* When re-bundling the evidence ZIP for a platform, regenerate\n"
        "  `SHA256SUMS` with `sources/build.py` (never hand-edit manifests).\n"
    )
    w(os.path.join("instructor", "scoring-rubric.md"), txt)


def write_siem_import_examples():
    spl = f"""\
# Optional SIEM import examples — the lab is fully solvable without these.

## Manual / plain parsing (works offline, no SIEM needed)

```python
import json
for line in open('artifacts/logs/incident-events.jsonl'):
    rec = json.loads(line)
    print(rec['timestamp_utc'], rec['source_event_id'], rec['category'])
```

## Splunk SPL (onboard each file as its own sourcetype)

Extract the row arrays into events:

```spl
index=eaitm_lab sourcetype=aitm:signins
| spath path=records{{}} output=recs
| mvexpand recs
| spath input=recs
| eval ts=coalesce(timestamp_utc, created_utc)
| sort 0 ts
```

Correlate by account and event ID across all datasets:

```spl
index=eaitm_lab
| eval event_id=coalesce(event_id, source_event_id, alert_id)
| stats values(source_dataset) AS sources, values(actor) AS actors,
        values(derived_summary) AS summary by event_id
```

Show everything involving the suspicious external IP (`{IP_ATTACKER}`):

```spl
index=eaitm_lab
| search "{IP_ATTACKER}"
| eval ts=coalesce(timestamp_utc, created_utc)
| sort 0 ts
```

## Elasticsearch / OpenSearch

Ingest each JSON file into an index (`eaitm-*`), then:

```json
GET eaitm-*/_search
{{
  "query": {{ "match_phrase": {{ "source_ip": "{IP_ATTACKER}" }} }},
  "sort": [{{ "timestamp_utc": "asc" }}]
}}
```

JSONL (one object per line) can be loaded with:

```python
import json
with open('artifacts/logs/incident-events.jsonl', encoding='utf-8') as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        # POST: PUT /eaitm-normalized/_doc/<id>
        print(rec['source_event_id'], json.dumps(rec))
```

## CSV workflow

`artifacts/logs/incident-timeline.csv` is a pre-sorted index of the
normalized stream: open it in any spreadsheet tool, filter by
`user_account`/`actor` or `category`, and pivot on the `event_id`.
"""
    w(os.path.join("tools", "optional-import-examples", "siem-imports.md"), spl)
