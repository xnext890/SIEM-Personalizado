"""Modelos de datos del pipeline: eventos normalizados y alertas."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Severidad de una alerta. IntEnum para poder ordenar/comparar."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name


# Tipos de evento que entiende el motor de detección. Cualquier línea que no
# encaje en un parser conocido se normaliza como OTHER (se guarda igualmente).
class EventType:
    SSH_FAILED_LOGIN = "ssh_failed_login"
    SSH_LOGIN_SUCCESS = "ssh_login_success"
    SSH_INVALID_USER = "ssh_invalid_user"
    SUDO_AUTH_FAILURE = "sudo_auth_failure"
    SUDO_COMMAND = "sudo_command"
    USER_CREATED = "user_created"
    OTHER = "other"


@dataclass
class Event:
    """Un evento de log ya normalizado, listo para almacenar y correlar."""

    timestamp: float
    host: str
    source: str  # proceso que generó la línea: sshd, sudo, useradd...
    event_type: str
    message: str  # línea original completa
    user: str | None = None
    src_ip: str | None = None


@dataclass
class Alert:
    """Resultado de una regla de detección que ha disparado."""

    rule: str
    severity: Severity
    entity: str  # IP o usuario sobre el que se alerta
    message: str
    timestamp: float = field(default_factory=time.time)
