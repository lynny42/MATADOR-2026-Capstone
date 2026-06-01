#!/usr/bin/env python3
"""Print incoming satellite TCP packets as pretty JSON."""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request


def _fetch(base_url: str, limit: int) -> list[dict]:
    url = f"{base_url.rstrip('/')}/api/telemetry/raw?limit={limit}"
    with urllib.request.urlopen(url, timeout=5) as response:
        payload = json.loads(response.read().decode("utf-8"))
    items = payload.get("items", [])
    return items if isinstance(items, list) else []


def _item_key(item: dict) -> str:
    return json.dumps(item, sort_keys=True, default=str)


def _print_item(item: dict) -> None:
    at = item.get("at", "?")
    peer = item.get("peer", "?")
    comm = item.get("comm_session", "")
    byte_length = item.get("byte_length", 0)
    parse_ok = item.get("parse_ok", False)
    header = f"\n{'=' * 72}\n[{at}] from {peer}"
    if comm:
        header += f" | {comm}"
    header += f" | {byte_length} bytes | parse_ok={parse_ok}"
    print(header)
    print("=" * 72)

    if item.get("parse_error"):
        print(f"PARSE ERROR: {item['parse_error']}")
        if item.get("raw_text"):
            print(item["raw_text"])
        return

    status = item.get("status")
    if isinstance(status, dict) and status:
        print(f"buffer status: {json.dumps(status, ensure_ascii=False, default=str)}")

    packet = item.get("packet")
    if isinstance(packet, dict):
        print(json.dumps(packet, ensure_ascii=False, indent=2, default=str))
    elif item.get("raw_text"):
        print(item["raw_text"])
    else:
        print("(empty payload)")


def main() -> int:
    parser = argparse.ArgumentParser(description="Watch raw satellite JSON packets")
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="API base URL")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--poll-sec", type=float, default=0.5)
    args = parser.parse_args()

    seen: set[str] = set()
    print(f"Watching {args.url}/api/telemetry/raw (Ctrl+C to stop)\n")

    try:
        while True:
            try:
                items = _fetch(args.url, args.limit)
            except urllib.error.URLError as error:
                print(f"API unreachable: {error}", file=sys.stderr)
                time.sleep(2.0)
                continue

            for item in reversed(items):
                key = _item_key(item)
                if key in seen:
                    continue
                seen.add(key)
                _print_item(item)

            if len(seen) > 2000:
                seen.clear()
            time.sleep(args.poll_sec)
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
