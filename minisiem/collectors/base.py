"""Base común de los collectors: un hilo daemon que emite líneas crudas."""

from __future__ import annotations

import queue
import threading


class BaseCollector(threading.Thread):
    """Hilo que produce líneas de log en la cola compartida del pipeline."""

    def __init__(self, out_queue: queue.Queue[str], name: str) -> None:
        super().__init__(name=f"collector-{name}", daemon=True)
        self.out_queue = out_queue
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    @property
    def stopped(self) -> bool:
        return self._stop_event.is_set()

    def emit(self, line: str) -> None:
        self.out_queue.put(line)
