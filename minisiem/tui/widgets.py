"""Widgets del dashboard: cabecera de stats, stream, alertas y top atacantes."""

from __future__ import annotations

import time
from collections import Counter, deque
from datetime import datetime

from rich.text import Text
from textual.widgets import DataTable, RichLog, Static

from ..models import Alert, Event, EventType, Severity

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on #c53b53",
    Severity.HIGH: "bold #ff757f",
    Severity.MEDIUM: "#ffc777",
    Severity.LOW: "#636da6",
}

EVENT_STYLE = {
    EventType.SSH_FAILED_LOGIN: ("AUTH-FAIL", "#ff757f"),
    EventType.SSH_LOGIN_SUCCESS: ("LOGIN-OK", "#c3e88d"),
    EventType.SSH_INVALID_USER: ("INV-USER", "#fca7ea"),
    EventType.SUDO_AUTH_FAILURE: ("SUDO-FAIL", "#ffc777"),
    EventType.SUDO_COMMAND: ("SUDO", "#82aaff"),
    EventType.USER_CREATED: ("NEW-USER", "#ff966c"),
    EventType.OTHER: ("SYS", "#636da6"),
}


def _clock(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")


class StatsBar(Static):
    """Cabecera con contadores en vivo: eventos, EPS y alertas por severidad."""

    EPS_WINDOW = 10.0

    def __init__(self) -> None:
        super().__init__()
        self.started_at = time.time()
        self.total_events = 0
        self.recent: deque[float] = deque()
        self.alert_counts: Counter[Severity] = Counter()

    def on_mount(self) -> None:
        self.set_interval(1.0, self.refresh_stats)
        self.refresh_stats()

    def record_event(self) -> None:
        self.total_events += 1
        self.recent.append(time.time())

    def record_alert(self, alert: Alert) -> None:
        self.alert_counts[alert.severity] += 1

    def refresh_stats(self) -> None:
        now = time.time()
        while self.recent and self.recent[0] < now - self.EPS_WINDOW:
            self.recent.popleft()
        eps = len(self.recent) / self.EPS_WINDOW
        uptime = int(now - self.started_at)

        text = Text()
        text.append("  ⛨ MiniSIEM  ", style="bold #82aaff")
        text.append("│ ", style="#2f334d")
        text.append(f"EVENTOS {self.total_events:>6}  ", style="bold white")
        text.append(f"{eps:>4.1f} eps  ", style="#636da6")
        text.append("│ ", style="#2f334d")
        for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
            count = self.alert_counts[severity]
            style = SEVERITY_STYLE[severity] if count else "#444a73"
            text.append(f" {severity.label} {count} ", style=style)
        text.append(" │ ", style="#2f334d")
        text.append(f"uptime {uptime // 60:02d}:{uptime % 60:02d}", style="#636da6")
        self.update(text)


class EventStream(RichLog):
    """Log en vivo de eventos normalizados, con badge de tipo coloreado."""

    def __init__(self) -> None:
        super().__init__(max_lines=500, auto_scroll=True)
        self.paused = False

    def add_event(self, event: Event) -> None:
        if self.paused:
            return
        badge, color = EVENT_STYLE.get(event.event_type, EVENT_STYLE[EventType.OTHER])
        line = Text()
        line.append(f"{_clock(event.timestamp)} ", style="#636da6")
        line.append(f"{badge:<9}", style=f"bold {color}")
        line.append(f" {event.host:<8}", style="#82aaff")
        detail = event.message.split(": ", 1)[-1]
        line.append(f" {detail}", style="#c8d3f5" if event.event_type != EventType.OTHER else "#565f89")
        self.write(line)


class AlertsTable(DataTable):
    """Tabla de alertas coloreada por severidad, con las más nuevas al final."""

    def on_mount(self) -> None:
        self.cursor_type = "row"
        self.zebra_stripes = True
        self.add_column("HORA", width=8)
        self.add_column("SEV", width=8)
        self.add_column("REGLA", width=24)
        self.add_column("ENTIDAD", width=15)
        self.add_column("DETALLE")

    def add_alert(self, alert: Alert) -> None:
        style = SEVERITY_STYLE[alert.severity]
        self.add_row(
            Text(_clock(alert.timestamp), style="#636da6"),
            Text(alert.severity.label, style=style),
            Text(alert.rule, style="#c8d3f5"),
            Text(alert.entity, style="bold #c8d3f5"),
            Text(alert.message, style="#828bb8"),
        )
        self.move_cursor(row=self.row_count - 1)


class TopAttackers(Static):
    """Ranking de IPs con más fallos de autenticación, con mini barra."""

    TOP_N = 5

    def __init__(self) -> None:
        super().__init__()
        self.counts: Counter[str] = Counter()

    def record_event(self, event: Event) -> None:
        if event.src_ip and event.event_type in (
            EventType.SSH_FAILED_LOGIN,
            EventType.SSH_INVALID_USER,
        ):
            self.counts[event.src_ip] += 1
            self.render_top()

    def render_top(self) -> None:
        top = self.counts.most_common(self.TOP_N)
        if not top:
            self.update(Text("  sin actividad hostil aún", style="#565f89"))
            return
        biggest = top[0][1]
        text = Text()
        for ip, count in top:
            bar = "█" * max(1, int(count / biggest * 14))
            text.append(f"  {ip:<16}", style="#c8d3f5")
            text.append(f"{bar:<15}", style="#ff757f")
            text.append(f" {count}\n", style="#636da6")
        self.update(text)
