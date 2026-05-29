from __future__ import annotations

import logging
import signal
import sqlite3
import threading

from ..db.db_manager import DBManager
from ..workers import AnomalyDetector, GScomms, SerialReader, UDPReceiver
from ..workers.false_positive_filter import (
    FalsePositiveFilter,
    PhysicalConsistencyModule,
    StatisticalConsistencyModule,
    SystemResponseModule,
)
from .context import DaemonConfig, RuntimeContext

logger = logging.getLogger(__name__)


class MatadorDaemon:
    """
    데몬 생명주기: init_db → SerialReader → UDPReceiver → AnomalyDetector(+FPF) → GScomms 기동,
    종료 시 join 후 cleanup.
    """

    def __init__(self, config: DaemonConfig | None = None) -> None:
        self._config = config or DaemonConfig()
        self._shutdown = threading.Event()
        self._threads: list[threading.Thread] = []
        self._db: DBManager | None = None

    @property
    def shutdown_event(self) -> threading.Event:
        return self._shutdown

    def request_shutdown(self) -> None:
        self._shutdown.set()

    def _signal_handler(self, signum: int, frame: object | None) -> None:
        logger.info("signal %s received, requesting shutdown", signum)
        self.request_shutdown()

    def _install_signals(self) -> None:
        try:
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
        except ValueError as e:
            logger.error("시그널 등록 실패(ValueError): %s", e)
        except OSError as e:
            logger.error("시그널 등록 실패(OSError): %s", e)
        except Exception as e:
            logger.error("시그널 등록 실패: %s", e)

    def run(self) -> int:
        self._install_signals()

        try:
            self._db = DBManager(self._config.db_path)
            if not self._db.init_db():
                logger.error("DBManager.init_db 실패")
                return 1
        except sqlite3.Error as e:
            logger.error("DBManager SQLite 오류: %s", e)
            return 1
        except Exception as e:
            logger.error("DBManager 기동 실패: %s", e)
            return 1

        try:
            ctx = RuntimeContext(
                config=self._config,
                shutdown_event=self._shutdown,
                db=self._db,
            )

            serial_reader = SerialReader(ctx)
            udp_receiver = UDPReceiver(ctx)
            anomaly_detector = AnomalyDetector(ctx)
            gs_comms = GScomms(ctx)
            gs_comms.set_serial_reader(serial_reader)
            gs_comms.set_anomaly_detector(anomaly_detector)

            false_positive_filter = FalsePositiveFilter(
                PhysicalConsistencyModule(self._db),
                StatisticalConsistencyModule(self._db),
                SystemResponseModule(self._db),
                gs_comms,
            )
            anomaly_detector.set_false_positive_filter(false_positive_filter)
            anomaly_detector.set_gs_comms(gs_comms)

            worker_specs: list[tuple[str, object]] = [
                ("SerialReader", serial_reader),
                ("UDPReceiver", udp_receiver),
                ("AnomalyDetector", anomaly_detector),
                ("GScomms", gs_comms),
            ]

            self._threads = [
                threading.Thread(target=w.run, name=name, daemon=False)
                for name, w in worker_specs
            ]

            for t in self._threads:
                t.start()
        except RuntimeError as e:
            logger.error("스레드 생성·시작 실패(RuntimeError): %s", e)
            return 1
        except Exception as e:
            logger.error("스레드 생성·시작 실패: %s", e)
            return 1

        try:
            while not self._shutdown.is_set():
                self._shutdown.wait(timeout=1.0)
        except Exception as e:
            logger.error("데몬 대기 루프 오류: %s", e)
        finally:
            self._join_all()
            self.cleanup()

        return 0

    def _join_all(self) -> None:
        self._shutdown.set()
        for t in self._threads:
            try:
                t.join(timeout=5.0)
            except RuntimeError as e:
                logger.error("스레드 join 실패(RuntimeError) %s: %s", t.name, e)
            except Exception as e:
                logger.error("스레드 join 실패 %s: %s", t.name, e)
            if t.is_alive():
                logger.warning("thread %s did not exit in time", t.name)

    def cleanup(self) -> None:
        try:
            if self._db is not None:
                self._db.close()
        except Exception as e:
            logger.error("DBManager cleanup 실패: %s", e)
        logger.info("cleanup complete")
