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