"""Orquestador: collectors -> cola -> parser -> storage + detección -> callbacks."""

from __future__ import annotations

import queue
import threading
from typing import Callable

from .collectors import BaseCollector
from .detection import DetectionEngine
from .models import Alert, Event
from .parsers import parse_line
from .storage import Storage

EventCallback = Callable[[Event], None]
AlertCallback = Callable[[Alert], None]


class Pipeline:
    """Consume las líneas de los collectors y las hace fluir por el SIEM.

    La TUI se engancha con `on_event` / `on_alert`; el pipeline no sabe nada
    de interfaces, solo de eventos.
    """

    def __init__(self, storage: Storage, engine: DetectionEngine) -> None:
        self.storage = storage
        self.engine = engine
        self.queue: queue.Queue[str] = queue.Queue()
        self.collectors: list[BaseCollector] = []
        self.on_event: EventCallback | None = None
        self.on_alert: AlertCallback | None = None
        self._worker: threading.Thread | None = None
        self._stop_event = threading.Event()

    def add_collector(self, collector: BaseCollector) -> None:
        self.collectors.append(collector)

    def start(self) -> None:
        self._worker = threading.Thread(target=self._run, name="pipeline", daemon=True)
        self._worker.start()
        for collector in self.collectors:
            collector.start()

    def stop(self) -> None:
        for collector in self.collectors:
            collector.stop()
        self._stop_event.set()
        if self._worker is not None:
            self._worker.join(timeout=2.0)

    def process_line(self, line: str) -> None:
        """Procesa una línea de log de principio a fin (parseo, storage, reglas)."""
        event = parse_line(line)
        if event is None:
            return
        self.storage.add_event(event)
        if self.on_event is not None:
            self.on_event(event)
        for alert in self.engine.process(event):
            self.storage.add_alert(alert)
            if self.on_alert is not None:
                self.on_alert(alert)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                line = self.queue.get(timeout=0.3)
            except queue.Empty:
                continue
            self.process_line(line)
