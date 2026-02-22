"""
build_all.py — full data pipeline runner.

Run with:
    python build_all.py

Steps
-----
  1. generate_companies.py    → companies.csv, company_trends.csv
  2. generate_personas.py     → personas.csv
  3. generate_transactions.py → transactions.parquet
  4. sauron/build_data.py     → Sauron analytics data

All analytics (forecast, fraud, stats) are now seeded directly
into the Sauron DB via seed_sauron.py — no more ML JSON files.

All scripts read N_PERSONAS (and SIZE_RANGE) from config.py — change the
number there and re-run this file to rebuild everything from scratch.
"""

import subprocess
import sys
import time
import os

PYTHON = sys.executable
ROOT   = os.path.dirname(__file__)

STEPS = [
    ("Companies & trends",   "generate_companies.py"),
    ("Personas",             "generate_personas.py"),
    ("Transactions",         "generate_transactions.py"),
    ("Sauron analytics data","sauron/build_data.py"),
]


def run_step(label: str, script: str) -> float:
    path = os.path.join(ROOT, script)
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"  {script}")
    print(f"{'='*60}")
    t0 = time.time()
    result = subprocess.run([PYTHON, path], cwd=ROOT)
    elapsed = time.time() - t0
    if result.returncode != 0:
        print(f"\n[FAILED] {script} exited with code {result.returncode}")
        sys.exit(result.returncode)
    print(f"  Done in {elapsed:.1f}s")
    return elapsed


def main():
    from config import N_PERSONAS, N_COMPANIES, SIZE_RANGE
    print(f"\nSauron / Dashboard — full pipeline rebuild")
    print(f"  N_PERSONAS  = {N_PERSONAS:,}")
    print(f"  N_COMPANIES = {N_COMPANIES}")
    print(f"  SIZE_RANGE  = {SIZE_RANGE}")
    print()

    total_t0 = time.time()
    timings  = []

    for label, script in STEPS:
        t = run_step(label, script)
        timings.append((label, t))

    total = time.time() - total_t0
    print(f"\n{'='*60}")
    print(f"  Pipeline complete in {total:.1f}s")
    print(f"{'='*60}")
    for label, t in timings:
        print(f"  {label:<30s}: {t:6.1f}s")
    print(f"  {'TOTAL':<30s}: {total:6.1f}s")


if __name__ == "__main__":
    main()
