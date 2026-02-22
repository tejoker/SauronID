"""
convert_stats_to_usd.py
Reads stats.csv (tab-separated, values in local currencies) and rewrites it
with all net-worth figures converted to USD.

Exchange rates sourced from open.er-api.com on 2026-02-21:
  1 USD = 0.741914 GBP  →  1 GBP = 1.347893 USD
  1 USD = 0.849025 EUR  →  1 EUR = 1.177810 USD
  1 USD = 9.061570 SEK  →  1 SEK = 0.110356 USD
  1 USD = 6.915665 CNY  →  1 CNY = 0.144602 USD
"""

import csv
import re
import os

# ---------------------------------------------------------------------------
# Exchange rates as of 2026-02-21 (source: open.er-api.com)
# ---------------------------------------------------------------------------
EXCHANGE_RATES_DATE = "2026-02-21"
TO_USD = {
    "USD": 1.000000,
    "GBP": 1 / 0.741914,   # 1.347893
    "EUR": 1 / 0.849025,   # 1.177810
    "SEK": 1 / 9.061570,   # 0.110356
    "CNY": 1 / 6.915665,   # 0.144602
    "RMB": 1 / 6.915665,   # same as CNY
}

# Map country prefix to currency
COUNTRY_CURRENCY = {
    "USA":  "USD",
    "UK":   "GBP",
    "FR":   "EUR",
    "IRE":  "EUR",
    "SWE":  "SEK",
    "CHN":  "CNY",
}

INPUT_FILE  = os.path.join(os.path.dirname(__file__), "stats.csv")
OUTPUT_FILE = INPUT_FILE  # overwrite in place


def parse_number(raw: str) -> float | None:
    """Strip any currency symbols, spaces and commas; return float or None."""
    cleaned = re.sub(r"[^\d.]", "", raw.strip())
    if not cleaned:
        return None
    return float(cleaned)


def detect_currency(country_cell: str) -> str:
    """Extract currency from a cell like 'USA (USD)' or 'CHN (RMB)'."""
    m = re.search(r"\(([A-Z]+)\)", country_cell)
    if m:
        return m.group(1)
    # Fallback: match by country prefix
    for prefix, currency in COUNTRY_CURRENCY.items():
        if country_cell.upper().startswith(prefix):
            return currency
    raise ValueError(f"Cannot detect currency from: {country_cell!r}")


def convert_row(row: list[str], currency: str) -> list[str]:
    """Convert columns 2-5 (net worth figures) from local currency to USD."""
    rate = TO_USD[currency]
    converted = row[:2]  # country, generation — unchanged
    for cell in row[2:6]:
        value = parse_number(cell)
        if value is None:
            converted.append("")
        else:
            converted.append(str(round(value * rate)))
    converted.append(row[6] if len(row) > 6 else "")  # source
    return converted


def main():
    with open(INPUT_FILE, encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f, delimiter="\t")
        raw_rows = list(reader)

    # Locate the header row (first row that contains "Generation")
    header_idx = next(
        i for i, r in enumerate(raw_rows) if any("Generation" in c for c in r)
    )
    header = raw_rows[header_idx]

    output_rows = []
    # Write a clean header
    output_rows.append([
        "country_currency",
        "generation_bracket",
        "median_net_worth_usd",
        "top25_threshold_usd",
        "top10_threshold_usd",
        "top1_threshold_usd",
        "source",
        "fx_rate_date",
    ])

    current_currency = None
    for row in raw_rows[header_idx + 1:]:
        if not any(c.strip() for c in row):
            continue  # skip blank lines
        # Update currency if the country cell is non-empty
        if row[0].strip():
            current_currency = detect_currency(row[0])
        if current_currency is None:
            continue
        converted = convert_row(row, current_currency)
        converted.append(EXCHANGE_RATES_DATE)
        output_rows.append(converted)

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerows(output_rows)

    data_rows = len(output_rows) - 1
    print(f"Converted {data_rows} rows → {OUTPUT_FILE}")
    print(f"Exchange rates date: {EXCHANGE_RATES_DATE}")
    for currency, rate in TO_USD.items():
        if currency != "RMB":
            print(f"  1 {currency} = {rate:.6f} USD")


if __name__ == "__main__":
    main()
