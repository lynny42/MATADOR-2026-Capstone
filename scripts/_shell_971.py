python -c "
import sys, json
from pathlib import Path
sys.path.insert(0, '.')
from scripts.reconstruct_bulk_from_db import reconstruct_bulk_from_rows, _load_bulk_groups
from ma_detector.db import config as db_config
from ma_detector.db.database import init_db, get_connection
from ma_detector.db.gs_repository import enrich_event_queue_row

init_db(db_config.DB_HOST, db_config.DB_PORT, db_config.DB_USER, db_config.DB_PASSWORD, db_config.DB_NAME, db_config.DB_POOL_SIZE)
groups = _load_bulk_groups()
key = sorted(groups.keys())[-1]
rows = groups[key]
bulk = reconstruct_bulk_from_rows(rows)

with get_connection() as conn:
    c = conn.cursor(dictionary=True)
    c.execute('SELECT * FROM gs_event_queue ORDER BY DETECTED_AT')
    events = []
    for r in c.fetchall():
        row = enrich_event_queue_row(dict(r))
        wire = row.get('PAYLOAD') if isinstance(row.get('PAYLOAD'), dict) else {}
        ev = {k: wire.get(k, row.get(k)) for k in [
            'EVENT_ID','EVENT_TYPE','PRIORITY','WEIGHT','SW_ID','DETECTED_AT','TIMESTAMP',
            'EXCEPTION_CODE','MODULE_SCORES','CHILDQUEUECOUNT','PIPEOVERFLOWRRCNT',
            'CMDREJECTEDCOUNTER','FILEWRITEERRCOUNTER','PROCESSOR_RESET_COUNT',
            'CH1_CH2_FAULT_CRC','CH1_FAULT_FILE_SIZE_MISMATCH','IS_SENT']}
        events.append(ev)
    c.close()

handoff = {
    'description': 'One SAT_BULK_TELEMETRY uplink reconstructed from local gs_tlm_history',
    'db_bulk_key': key,
    'comm_session': rows[0].get('COMM_SESSION'),
    'snapshot_count': len(rows),
    'snapshot_ids': [r.get('SNAPSHOT_ID') for r in rows],
    'sw_id_subsystem_map': {'0': 'ADCS', '1': 'OBC', '2': 'EPS', '3': 'COM'},
    'SAT_BULK_TELEMETRY': bulk,
    'SAT_EVENT_QUEUE': {'events': events},
}
out = Path('backend/test_data/claude_attack_scenario_uplink.json')
out.write_text(json.dumps(handoff, ensure_ascii=False, indent=2, default=str), encoding='utf-8')
print('wrote', out, 'bytes', out.stat().st_size)
print('events', len(events))
"