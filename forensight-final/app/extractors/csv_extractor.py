from __future__ import annotations

import csv
from pathlib import Path
from typing import Any


def extract_csv(path: str | Path) -> list[dict[str, Any]]:
    with open(path, "r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("CSV has no header row")
        return [dict(row) for row in reader]
