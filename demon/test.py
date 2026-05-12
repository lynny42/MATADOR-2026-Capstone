import socket
import time
from collections import defaultdict

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 5020
CAPTURE_SECONDS = 60
SAMPLES_PER_MID = 2
FOCUS_MID = 0x1ACF


def parse_packet(data: bytes, offset: int):
    try:
        if offset + 6 > len(data):
            return None
        w0 = (data[offset] << 8) | data[offset + 1]
        w1 = (data[offset + 2] << 8) | data[offset + 3]
        pdl = (data[offset + 4] << 8) | data[offset + 5]
        total = 6 + pdl + 1
        if total <= 6 or offset + total > len(data):
            return None
        version = (w0 >> 13) & 0x07
        ptype = (w0 >> 12) & 0x01
        sec_hdr = (w0 >> 11) & 0x01
        apid = w0 & 0x07FF
        seq_flag = (w1 >> 14) & 0x03
        seq_cnt = w1 & 0x3FFF
        return {
            "mid": w0,
            "total": total,
            "version": version,
            "type": ptype,
            "sec_hdr": sec_hdr,
            "apid": apid,
            "seq_flag": seq_flag,
            "seq_cnt": seq_cnt,
            "raw": bytes(data[offset:offset + total]),
        }
    except Exception as e:
        print(f"parse error: {e}")
        return None


def is_valid_cfs_header(info: dict) -> bool:
    if info["version"] != 0:
        return False
    if info["sec_hdr"] != 1:
        return False
    return True


def hex_dump(buf: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(buf), width):
        chunk = buf[i:i + width]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:04X}  {hex_part:<{width * 3}}  {ascii_part}")
    return "\n".join(lines)


def main():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((LISTEN_HOST, LISTEN_PORT))
        sock.settimeout(1.0)
    except Exception as e:
        print(f"socket bind 실패: {e}")
        return

    stats = defaultdict(lambda: {
        "count": 0,
        "size": 0,
        "type": 0,
        "apid": 0,
        "sec_hdr": 0,
        "version": 0,
        "valid_cfs": False,
        "samples": [],
        "seq_min": None,
        "seq_max": None,
    })
    start = time.time()
    pkt_total = 0
    drift_total = 0

    print(f"{LISTEN_PORT} 포트 {CAPTURE_SECONDS}초 동안 수집 시작...")
    while time.time() - start < CAPTURE_SECONDS:
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except Exception as e:
            print(f"recv 오류: {e}")
            break

        offset = 0
        while offset + 6 <= len(data):
            info = parse_packet(data, offset)
            if info is None:
                drift_total += 1
                break
            mid = info["mid"]
            s = stats[mid]
            s["count"] += 1
            s["size"] = info["total"]
            s["type"] = info["type"]
            s["apid"] = info["apid"]
            s["sec_hdr"] = info["sec_hdr"]
            s["version"] = info["version"]
            s["valid_cfs"] = is_valid_cfs_header(info)
            if s["seq_min"] is None or info["seq_cnt"] < s["seq_min"]:
                s["seq_min"] = info["seq_cnt"]
            if s["seq_max"] is None or info["seq_cnt"] > s["seq_max"]:
                s["seq_max"] = info["seq_cnt"]
            if len(s["samples"]) < SAMPLES_PER_MID:
                s["samples"].append(info["raw"])
            pkt_total += 1
            offset += info["total"]

    sock.close()

    print(f"\n=== 수집 요약: 총 {pkt_total} 패킷, {len(stats)} 종류 MID, 오정렬 추정 {drift_total}회 ===")
    print(f"{'MID':>8} {'VALID':>6} {'TYPE':>5} {'VER':>4} {'SH':>3} "
          f"{'APID':>6} {'SIZE':>5} {'SEQ_MIN':>8} {'SEQ_MAX':>8} {'COUNT':>6}")

    for mid in sorted(stats.keys(), key=lambda k: -stats[k]["count"]):
        s = stats[mid]
        type_str = "CMD" if s["type"] == 1 else "TLM"
        valid_str = "O" if s["valid_cfs"] else "X"
        print(
            f"0x{mid:04X} {valid_str:>6} {type_str:>5} {s['version']:>4} {s['sec_hdr']:>3} "
            f"0x{s['apid']:03X} {s['size']:>5} {str(s['seq_min']):>8} {str(s['seq_max']):>8} "
            f"{s['count']:>6}"
        )

    for mid in sorted(stats.keys(), key=lambda k: -stats[k]["count"]):
        s = stats[mid]
        if s["count"] < 1:
            continue
        if not s["valid_cfs"] and mid != FOCUS_MID:
            continue
        print(f"\n--- MID 0x{mid:04X} 샘플 ({len(s['samples'])}개, size={s['size']}) ---")
        for idx, raw in enumerate(s["samples"]):
            print(f"[sample {idx}] len={len(raw)}")
            print(hex_dump(raw))


if __name__ == "__main__":
    main()
