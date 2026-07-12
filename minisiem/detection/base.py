"""Piezas comunes de las reglas de detección."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import defaultdict, deque

from ..models import Alert, Event, Severity


class SlidingWindow:
    """Contador de ocurrencias por clave (IP, usuario...) en una ventana de tiempo.

    Cada regla que necesita umbrales tipo "N eventos en X segundos" reutiliza
    esta clase en lugar de implementar su propia contabilidad.
    """

    def __init__(self, window_seconds: float) -> None:
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def add(self, key: str, timestamp: float) -> int:
        """Registra una ocurrencia y devuelve cuántas hay vivas en la ventana."""
        hits = self._hits[key]
        hits.append(timestamp)
        self._prune(hits, timestamp)
        return len(hits)

    def count(self, key: str, timestamp: float) -> int:
        hits = self._hits.get(key)
        if not hits:
            return 0
        self._prune(hits, timestamp)
        return len(hits)

    def clear(self, key: str) -> None:
        self._hits.pop(key, None)

    def _prune(self, hits: deque[float], now: float) -> None:
        cutoff = now - self.window_seconds
        while hits and hits[0] < cutoff:
            hits.popleft()


class BaseRule(ABC):
    """Interfaz de una regla: recibe eventos y opcionalmente emite una alerta."""

    name: str = "base"
    severity: Severity = Severity.LOW

    @abstractmethod
    def check(self, event: Event) -> Alert | None: ...

    def alert(self, entity: str, message: str, timestamp: float) -> Alert:
        return Alert(
            rule=self.name,
            severity=self.severity,
            entity=entity,
            message=message,
            timestamp=timestamp,
        )
