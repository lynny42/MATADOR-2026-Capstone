"""Build pipeline_cases.json from transcript extract."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "backend" / "test_data" / "_transcript_case_extract.txt"
OUT = ROOT / "backend" / "test_data" / "pipeline_cases.json"

SECTIONS = {
    "1": "정상만 존재하는 경우",
    "2": "오탐만 존재하는 경우",
    "3": "해시 무결성이 훼손된 경우",
    "4": "공격이 존재하는 경우",
}


def _extract_json_blocks(body: str) -> list[dict]:
    blocks: list[dict] = []
    marker = "```jsx"
    pos = 0
    while True:
        start_marker = body.find(marker, pos)
        if start_marker < 0:
            break
        start = body.find("{", start_marker)
        if start < 0:
            break
        depth = 0
        end = start
        for index, char in enumerate(body[start:], start):
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end = index
                    break
        blocks.append(json.loads(body[start : end + 1]))
        pos = end + 1
    return blocks


def main() -> None:
    text = SRC.read_text(encoding="utf-8")
    parts = re.split(r"^# ([^#\n].+)$", text, flags=re.M)
    cases: dict[str, dict] = {}
    for index in range(1, len(parts), 2):
        title = parts[index].strip()
        body = parts[index + 1] if index + 1 < len(parts) else ""
        case_id = None
        for cid, label in SECTIONS.items():
            if label in title:
                case_id = cid
                break
        if case_id is None:
            continue
        packets = _extract_json_blocks(body)
        cases[case_id] = {"title": title, "packets": packets}

    OUT.write_text(json.dumps({"cases": cases}, ensure_ascii=False, indent=2), encoding="utf-8")
    for cid, data in cases.items():
        print(f"case {cid}: {len(data['packets'])} packets")


if __name__ == "__main__":
    main()
