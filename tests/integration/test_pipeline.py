"""HTTP integration tests for buffered telemetry pipeline cases."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CASES_PATH = ROOT / "backend" / "test_data" / "pipeline_cases.json"
DEFAULT_BASE_URL = "http://localhost:8000"
RECEIVE_PATH = "/api/telemetry/receive"
RECENT_PATH = "/api/dashboard/recent"


def _load_cases() -> dict[str, dict]:
    payload = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    cases = payload.get("cases", {})
    if not cases:
        raise RuntimeError(f"no cases found in {CASES_PATH}")
    return cases


def _post_json(base_url: str, path: str, body: dict) -> dict:
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read().decode("utf-8")
        return json.loads(raw) if raw else {}


def _get_json(base_url: str, path: str) -> dict:
    request = urllib.request.Request(f"{base_url.rstrip('/')}{path}", method="GET")
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read().decode("utf-8")
        return json.loads(raw) if raw else {}


def run_case(base_url: str, case_id: str, case_data: dict) -> None:
    packets = case_data.get("packets", [])
    title = case_data.get("title", case_id)
    print(f"\n=== Case {case_id}: {title} ({len(packets)} packets) ===")
    for index, packet in enumerate(packets, start=1):
        packet_type = packet.get("packet_type", "UNKNOWN")
        try:
            response = _post_json(base_url, RECEIVE_PATH, packet)
            print(f"[{index}] POST {packet_type} -> {response}")
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"case {case_id} packet {index} failed: {error.code} {detail}") from error
        time.sleep(0.2)

    if case_id in {"3", "4"}:
        time.sleep(1.0)
        recent = _get_json(base_url, RECENT_PATH)
        print(f"Recent dashboard detections: {json.dumps(recent, ensure_ascii=False, indent=2)}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Inject MATADOR pipeline test cases over HTTP")
    parser.add_argument("--case", choices=["1", "2", "3", "4"], help="Run one case")
    parser.add_argument("--all", action="store_true", help="Run all cases")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="FastAPI base URL")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    if not args.case and not args.all:
        parser.error("Specify --case or --all")

    cases = _load_cases()
    selected = sorted(cases.keys()) if args.all else [args.case]
    for case_id in selected:
        if case_id not in cases:
            raise RuntimeError(f"case {case_id} missing from {CASES_PATH}")
        run_case(args.base_url, case_id, cases[case_id])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
