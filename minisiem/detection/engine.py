"""Motor de detección: pasa cada evento por todas las reglas y deduplica."""

from __future__ import annotations

from ..models import Alert, Event
from .base import BaseRule
from .rules import (
    InvalidUserSprayRule,
    NewUserCreatedRule,
    RootLoginRule,
    SSHBruteForceRule,
    SSHSuccessAfterFailuresRule,
    SudoFailureRule,
)


def default_rules() -> list[BaseRule]:
    return [
        SSHBruteForceRule(),
        SSHSuccessAfterFailuresRule(),
        RootLoginRule(),
        InvalidUserSprayRule(),
        SudoFailureRule(),
        NewUserCreatedRule(),
    ]


class DetectionEngine:
    """Evalúa eventos contra las reglas, suprimiendo alertas repetidas.

    Si una misma regla vuelve a disparar para la misma entidad dentro del
    periodo de enfriamiento, la alerta se descarta para no inundar el panel.
    """

    def __init__(self, rules: list[BaseRule] | None = None, cooldown_seconds: float = 60.0):
        self.rules = rules if rules is not None else default_rules()
        self.cooldown_seconds = cooldown_seconds
        self._last_fired: dict[tuple[str, str], float] = {}

    def process(self, event: Event) -> list[Alert]:
        alerts: list[Alert] = []
        for rule in self.rules:
            alert = rule.check(event)
            if alert is None:
                continue
            key = (alert.rule, alert.entity)
            last = self._last_fired.get(key)
            if last is not None and alert.timestamp - last < self.cooldown_seconds:
                continue
            self._last_fired[key] = alert.timestamp
            alerts.append(alert)
        return alerts
