"""Parser de líneas estilo syslog de Linux (auth.log / syslog).

Convierte líneas crudas en objetos Event normalizados. Soporta las cabeceras
syslog tradicional ("Jul 12 01:15:30") y RFC 3339 de rsyslog moderno.
"""

from __future__ import annotations

import re
import time
from datetime import datetime

from ..models import Event, EventType

# Cabecera syslog tradicional: "Jul 12 01:15:30 host proceso[pid]: mensaje"
_HEADER_BSD = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[\w./-]+)(?:\[\d+\])?:\s+"
    r"(?P<msg>.*)$"
)

# Cabecera RFC 3339: "2026-07-12T01:15:30.123456+02:00 host proceso[pid]: mensaje"
_HEADER_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[\w./-]+)(?:\[\d+\])?:\s+"
    r"(?P<msg>.*)$"
)

_SSH_FAILED = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
)
_SSH_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+)"
)
_SSH_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")
_SUDO_AUTH_FAIL = re.compile(
    r"pam_unix\(sudo:auth\): authentication failure;.*\buser=(?P<user>\S+)"
)
_SUDO_INCORRECT = re.compile(r"^\s*(?P<user>\S+) : .*incorrect password attempts?")
_SUDO_COMMAND = re.compile(r"^\s*(?P<user>\S+) : .*COMMAND=(?P<cmd>.+)$")
_USER_CREATED = re.compile(r"new user: name=(?P<user>[^,]+)")


def _parse_timestamp(raw: str) -> float:
    """Epoch a partir de la cabecera. Si algo falla, la hora actual."""
    try:
        if raw[0].isdigit():
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
        # Formato BSD sin año: asumimos el año en curso.
        parsed = datetime.strptime(raw, "%b %d %H:%M:%S")
        return parsed.replace(year=datetime.now().year).timestamp()
    except ValueError:
        return time.time()


def parse_line(line: str) -> Event | None:
    """Parsea una línea de log. Devuelve None para líneas vacías/sin cabecera."""
    line = line.rstrip("\n")
    if not line.strip():
        return None

    match = _HEADER_BSD.match(line) or _HEADER_ISO.match(line)
    if match is None:
        return None

    timestamp = _parse_timestamp(match.group("ts"))
    host = match.group("host")
    proc = match.group("proc")
    msg = match.group("msg")

    event_type = EventType.OTHER
    user: str | None = None
    src_ip: str | None = None

    if proc == "sshd":
        if m := _SSH_FAILED.search(msg):
            event_type = EventType.SSH_FAILED_LOGIN
            user, src_ip = m.group("user"), m.group("ip")
        elif m := _SSH_ACCEPTED.search(msg):
            event_type = EventType.SSH_LOGIN_SUCCESS
            user, src_ip = m.group("user"), m.group("ip")
        elif m := _SSH_INVALID.search(msg):
            event_type = EventType.SSH_INVALID_USER
            user, src_ip = m.group("user"), m.group("ip")
    elif proc == "sudo":
        if m := _SUDO_AUTH_FAIL.search(msg):
            event_type = EventType.SUDO_AUTH_FAILURE
            user = m.group("user")
        elif m := _SUDO_INCORRECT.match(msg):
            event_type = EventType.SUDO_AUTH_FAILURE
            user = m.group("user")
        elif m := _SUDO_COMMAND.match(msg):
            event_type = EventType.SUDO_COMMAND
            user = m.group("user")
    elif proc in ("useradd", "adduser"):
        if m := _USER_CREATED.search(msg):
            event_type = EventType.USER_CREATED
            user = m.group("user").strip()

    return Event(
        timestamp=timestamp,
        host=host,
        source=proc,
        event_type=event_type,
        message=line,
        user=user,
        src_ip=src_ip,
    )
