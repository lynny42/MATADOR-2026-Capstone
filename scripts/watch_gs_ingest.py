#!/usr/bin/env python3
"""Poll /api/telemetry/recent and print new satellite ingest events."""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request


def _fetch(base_url: str, limit: int) -> list[dict]:
    url = f"{base_url.rstrip('/')}/api/telemetry/recent?limit={limit}"
    with urllib.request.urlopen(url, timeout=5) as response:
        payload = json.loads(response.read().decode("utf-8"))
    items = payload.get("items", [])
    return items if isinstance(items, list) else []


def _format_line(item: dict) -> str:
    at = item.get("at", "?")
    stage = item.get("stage", "?")
    ptype = item.get("packet_type", "")
    summary = item.get("summary", "")
    status = item.get("status", {})
    peer = item.get("peer", "")
    buffer_key = item.get("buffer_key", "")
    comm_session = item.get("comm_session", "")

    parts = [f"[{at}]", stage]
    if comm_session:
        parts.append(comm_session)
    if ptype:
        parts.append(ptype)
    if summary:
        parts.append(summary)
    if isinstance(status, dict) and status.get("status"):
        parts.append(f"-> {status.get('status')}")
        received = status.get("received")
        if isinstance(received, list) and received:
            parts.append(f"buf={received}")
    if buffer_key:
        parts.append(f"key={buffer_key}")
    if peer:
        parts.append(f"from {peer}")
    extra = item.get("extra")
    if isinstance(extra, dict) and extra:
        parts.append(f"extra={extra}")
    return " | ".join(str(part) for part in parts if part)


def main() -> int:
    parser = argparse.ArgumentParser(description="Watch ground-station ingest trace")
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="API base URL")
    parser.add_argument("--limit", type=int, default=30)
    parser.add_argument("--poll-sec", type=float, default=0.5)
    args = parser.parse_args()

    seen: set[str] = set()
    print(f"Watching {args.url}/api/telemetry/recent (Ctrl+C to stop)\n")

    try:
        while True:
            try:
                items = _fetch(args.url, args.limit)
            except urllib.error.URLError as error:
                print(f"API unreachable: {error}", file=sys.stderr)
                time.sleep(2.0)
                continue

            for item in reversed(items):
                key = json.dumps(item, sort_keys=True, default=str)
                if key in seen:
                    continue
                seen.add(key)
                print(_format_line(item))

            if len(seen) > 5000:
                seen.clear()
            time.sleep(args.poll_sec)
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
