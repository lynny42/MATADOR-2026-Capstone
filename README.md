# MATADOR-2026-Capstone

## MA Integrated Detector

`ma_detector/` contains the ground-station MA integrated detection code generator.

Main entry point:

```python
from ma_detector import MAIntegratedDetector

detector = MAIntegratedDetector()
detector.build_baseline(normal_history)
detector.receive_telemetry(json_token)
```

The pipeline follows:

1. `receive_telemetry`
2. `evaluate_parallel_rules`
3. `verify_attack_sequence`
4. `generate_ma_code`
5. `insert_dashboard_db`
6. `get_ui_data`

Rule/action/threshold definitions are stored under `ma_detector/config/`.

## Ground-station Dashboard

This branch also includes a FastAPI backend and a Next.js dashboard UI.

### Backend

```bash
python3 -m pip install -r requirements.txt
uvicorn backend.app:app --reload --host 0.0.0.0 --port 8000
```

Important API endpoints:

- `GET /api/dashboard` - latest communications, recent threats, blueprint state, and MA codes
- `GET /api/detections/{detect_id}` - selected MA code detail and triggered rule evidence
- `POST /api/telemetry` - receive the satellite JSON and refresh dashboard state
- `GET /api/rules` - current rule, action, and threshold settings
- `POST /api/replay` - replay packets after rule/threshold edits

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Set `NEXT_PUBLIC_API_URL=http://localhost:8000` if the API runs on a different host.

Dashboard features:

- Left blueprint for OBC, TCS, EPS, ADCS, and COM
- Recent 5-communication threat highlights by subsystem
- Emphasis by phase and confidence
- Right-side latest communication result and chronological MA code list
- Search/select control for stored MA codes
- Rule evidence details for selected codes
- Rule/threshold panel with replay support