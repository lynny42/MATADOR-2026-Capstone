#!/usr/bin/env python3
"""Print incoming satellite TCP packets as pretty JSON."""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request


def _fetch_list(base_url: str, limit: int) -> list[dict]:
    url = f"{base_url.rstrip('/')}/api/telemetry/raw?limit={limit}"
    with urllib.request.urlopen(url, timeout=30) as response:
        payload = json.loads(response.read().decode("utf-8"))
    items = payload.get("items", [])
    return items if isinstance(items, list) else []


def _fetch_detail(base_url: str, entry_id: int) -> dict | None:
    url = f"{base_url.rstrip('/')}/api/telemetry/raw/{entry_id}"
    with urllib.request.urlopen(url, timeout=120) as response:
        payload = json.loads(response.read().decode("utf-8"))
    return payload if isinstance(payload, dict) else None


def _fetch_wire(base_url: str, entry_id: int) -> str:
    url = f"{base_url.rstrip('/')}/api/telemetry/raw/{entry_id}?wire=1"
    with urllib.request.urlopen(url, timeout=120) as response:
        return response.read().decode("utf-8")


def _item_key(item: dict) -> str:
    entry_id = item.get("id")
    if entry_id is not None:
        return str(entry_id)
    return json.dumps(item, sort_keys=True, default=str)


def _print_item(item: dict, *, wire: bool) -> None:
    at = item.get("at", "?")
    peer = item.get("peer", "?")
    comm = item.get("comm_session", "")
    byte_length = item.get("byte_length", item.get("raw_byte_length", 0))
    parse_ok = item.get("parse_ok", False)
    entry_id = item.get("id", "?")
    header = f"\n{'=' * 72}\n[id={entry_id}] [{at}] from {peer}"
    if comm:
        header += f" | {comm}"
    header += f" | {byte_length} bytes | parse_ok={parse_ok}"
    if item.get("raw_spooled"):
        header += " | spooled"
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

    if wire and isinstance(item.get("raw_text"), str) and item["raw_text"]:
        print(item["raw_text"])
        return

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
    parser.add_argument(
        "--wire",
        action="store_true",
        help="Print original TCP wire JSON (key order preserved when spooled from TCP)",
    )
    parser.add_argument("--id", type=int, help="Fetch and print one stored packet id, then exit")
    args = parser.parse_args()

    if args.id is not None:
        try:
            if args.wire:
                print(_fetch_wire(args.url, args.id))
            else:
                item = _fetch_detail(args.url, args.id)
                if item is None:
                    print(f"Not found: id={args.id}", file=sys.stderr)
                    return 1
                _print_item(item, wire=args.wire)
        except urllib.error.HTTPError as error:
            print(f"Fetch failed: {error.code} {error.read().decode('utf-8', errors='replace')}", file=sys.stderr)
            return 1
        return 0

    seen: set[str] = set()
    print(f"Watching {args.url}/api/telemetry/raw (Ctrl+C to stop)\n")

    try:
        while True:
            try:
                items = _fetch_list(args.url, args.limit)
            except urllib.error.URLError as error:
                print(f"API unreachable: {error}", file=sys.stderr)
                time.sleep(2.0)
                continue

            for item in reversed(items):
                key = _item_key(item)
                if key in seen:
                    continue
                seen.add(key)
                entry_id = item.get("id")
                if entry_id is None:
                    _print_item(item, wire=args.wire)
                    continue
                try:
                    if args.wire:
                        wire_text = _fetch_wire(args.url, int(entry_id))
                        detail = dict(item)
                        detail["raw_text"] = wire_text
                        _print_item(detail, wire=True)
                    else:
                        detail = _fetch_detail(args.url, int(entry_id))
                        if detail is not None:
                            _print_item(detail, wire=False)
                except urllib.error.URLError as error:
                    print(f"id={entry_id} fetch failed: {error}", file=sys.stderr)

            if len(seen) > 2000:
                seen.clear()
            time.sleep(args.poll_sec)
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
