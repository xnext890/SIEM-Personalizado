"""Reglas de detección incluidas de serie."""

from __future__ import annotations

from ..models import Alert, Event, EventType, Severity
from .base import BaseRule, SlidingWindow


class SSHBruteForceRule(BaseRule):
    """≥5 contraseñas fallidas desde la misma IP en 60 segundos."""

    name = "ssh_brute_force"
    severity = Severity.HIGH
    THRESHOLD = 5
    WINDOW = 60.0

    def __init__(self) -> None:
        self._failures = SlidingWindow(self.WINDOW)

    def check(self, event: Event) -> Alert | None:
        if event.event_type != EventType.SSH_FAILED_LOGIN or not event.src_ip:
            return None
        count = self._failures.add(event.src_ip, event.timestamp)
        if count == self.THRESHOLD:
            return self.alert(
                entity=event.src_ip,
                message=f"Posible fuerza bruta SSH: {count} fallos de login desde "
                f"{event.src_ip} en {int(self.WINDOW)}s (último usuario: {event.user})",
                timestamp=event.timestamp,
            )
        return None


class SSHSuccessAfterFailuresRule(BaseRule):
    """Login exitoso desde una IP que acumulaba fallos recientes: brute force que ha entrado."""

    name = "ssh_success_after_failures"
    severity = Severity.CRITICAL
    MIN_FAILURES = 3
    WINDOW = 300.0

    def __init__(self) -> None:
        self._failures = SlidingWindow(self.WINDOW)

    def check(self, event: Event) -> Alert | None:
        if not event.src_ip:
            return None
        if event.event_type == EventType.SSH_FAILED_LOGIN:
            self._failures.add(event.src_ip, event.timestamp)
            return None
        if event.event_type == EventType.SSH_LOGIN_SUCCESS:
            failures = self._failures.count(event.src_ip, event.timestamp)
            if failures >= self.MIN_FAILURES:
                self._failures.clear(event.src_ip)
                return self.alert(
                    entity=event.src_ip,
                    message=f"Login SSH exitoso de '{event.user}' desde {event.src_ip} "
                    f"tras {failures} fallos recientes: posible intrusión",
                    timestamp=event.timestamp,
                )
        return None


class RootLoginRule(BaseRule):
    """Cualquier login SSH aceptado como root."""

    name = "root_ssh_login"
    severity = Severity.HIGH

    def check(self, event: Event) -> Alert | None:
        if event.event_type == EventType.SSH_LOGIN_SUCCESS and event.user == "root":
            return self.alert(
                entity=event.src_ip or "?",
                message=f"Login SSH como root desde {event.src_ip}",
                timestamp=event.timestamp,
            )
        return None


class InvalidUserSprayRule(BaseRule):
    """≥5 intentos con usuarios inexistentes desde la misma IP en 120s: enumeración."""

    name = "invalid_user_spray"
    severity = Severity.MEDIUM
    THRESHOLD = 5
    WINDOW = 120.0

    def __init__(self) -> None:
        self._attempts = SlidingWindow(self.WINDOW)

    def check(self, event: Event) -> Alert | None:
        if event.event_type != EventType.SSH_INVALID_USER or not event.src_ip:
            return None
        count = self._attempts.add(event.src_ip, event.timestamp)
        if count == self.THRESHOLD:
            return self.alert(
                entity=event.src_ip,
                message=f"Enumeración de usuarios desde {event.src_ip}: "
                f"{count} usuarios inválidos en {int(self.WINDOW)}s",
                timestamp=event.timestamp,
            )
        return None


class SudoFailureRule(BaseRule):
    """≥3 fallos de autenticación sudo del mismo usuario en 5 minutos."""

    name = "sudo_failures"
    severity = Severity.MEDIUM
    THRESHOLD = 3
    WINDOW = 300.0

    def __init__(self) -> None:
        self._failures = SlidingWindow(self.WINDOW)

    def check(self, event: Event) -> Alert | None:
        if event.event_type != EventType.SUDO_AUTH_FAILURE or not event.user:
            return None
        count = self._failures.add(event.user, event.timestamp)
        if count == self.THRESHOLD:
            return self.alert(
                entity=event.user,
                message=f"El usuario '{event.user}' acumula {count} fallos de sudo "
                f"en {int(self.WINDOW / 60)} min: posible intento de escalada",
                timestamp=event.timestamp,
            )
        return None


class NewUserCreatedRule(BaseRule):
    """Creación de una cuenta local: técnica clásica de persistencia."""

    name = "new_user_created"
    severity = Severity.MEDIUM

    def check(self, event: Event) -> Alert | None:
        if event.event_type == EventType.USER_CREATED:
            return self.alert(
                entity=event.user or "?",
                message=f"Cuenta local creada: '{event.user}' en {event.host}",
                timestamp=event.timestamp,
            )
        return None
