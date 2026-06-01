"""MySQL connection settings for the ground-station database."""

DB_HOST = "127.0.0.1"
DB_PORT = 3306
DB_USER = "matador"
DB_PASSWORD = "4396"
DB_NAME = "matador_gs"
DB_POOL_SIZE = 5

# Actual MySQL table names (lowercase on deployed schema)
TABLE_TLM_HISTORY = "gs_tlm_history"
TABLE_PWR_META = "gs_pwr_meta"
TABLE_ANOMALY_DASHBOARD = "gs_anomaly_ma_dashboard"
TABLE_ANOMALY_DETAIL = "gs_anomaly_detail"
TABLE_ANOMALY_DISCARD_LOG = "gs_anomaly_discard_log"
