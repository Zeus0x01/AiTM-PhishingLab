#!/usr/bin/env python3
"""Orchestrator: full deterministic build.

python sources/main.py            # full build + validate + package
python sources/main.py --check    # validate + package only (uses existing files)
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import build
import gen_artifacts
import build2
import build3
import portal
import package
import validate


def main():
    rebuild = "--check" not in sys.argv
    t0 = time.time()
    if rebuild:
        print("[1/5] core artifacts")
        gen_artifacts.main()
        print("[2/5] docs")
        build2.write_readme()
        build2.write_safety()
        build2.write_field_reference()
        build2.write_evidence_inventory()
        build3.write_short_answer_questions()
        print("[3/5] instructor pack")
        build3.write_question_bank()
        build3.write_answer_key()
        build3.write_scoring_rubric()
        build3.write_siem_import_examples()
        print("[4/5] portal + offline twin")
        portal.write_portal()
        portal.write_offline_twin()
        print("[5/5] package")
        package.package()
        print(f"build complete in {time.time()-t0:.1f}s")
    validate.run_all()
    print("AI-LAB-VALIDATION-PASS")


if __name__ == "__main__":
    main()
