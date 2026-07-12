"""Persistencia en SQLite de eventos y alertas.

Una única conexión compartida protegida con un Lock: el pipeline escribe desde
su hilo y la TUI (o los tests) pueden consultar desde otro.
"""

from __future__ import annotations

import sqlite3
import threading

from .models import Alert, Event, Severity

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,
    host       TEXT NOT NULL,
    source     TEXT NOT NULL,
    event_type TEXT NOT NULL,
    user       TEXT,
    src_ip     TEXT,
    message    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events (src_ip);

CREATE TABLE IF NOT EXISTS alerts (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    rule     TEXT NOT NULL,
    severity INTEGER NOT NULL,
    entity   TEXT NOT NULL,
    message  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts (ts);
"""


class Storage:
    def __init__(self, path: str = "minisiem.db") -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def add_event(self, event: Event) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO events (ts, host, source, event_type, user, src_ip, message)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    event.timestamp,
                    event.host,
                    event.source,
                    event.event_type,
                    event.user,
                    event.src_ip,
                    event.message,
                ),
            )
            self._conn.commit()

    def add_alert(self, alert: Alert) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO alerts (ts, rule, severity, entity, message) VALUES (?, ?, ?, ?, ?)",
                (alert.timestamp, alert.rule, int(alert.severity), alert.entity, alert.message),
            )
            self._conn.commit()

    def event_count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()
        return row["n"]

    def alert_count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()
        return row["n"]

    def recent_alerts(self, limit: int = 50) -> list[Alert]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, rule, severity, entity, message FROM alerts ORDER BY ts DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            Alert(
                rule=row["rule"],
                severity=Severity(row["severity"]),
                entity=row["entity"],
                message=row["message"],
                timestamp=row["ts"],
            )
            for row in rows
        ]

    def top_attackers(self, limit: int = 5) -> list[tuple[str, int]]:
        """IPs con más eventos de fallo de autenticación / usuario inválido."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT src_ip, COUNT(*) AS n FROM events"
                " WHERE src_ip IS NOT NULL"
                "   AND event_type IN ('ssh_failed_login', 'ssh_invalid_user')"
                " GROUP BY src_ip ORDER BY n DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [(row["src_ip"], row["n"]) for row in rows]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
