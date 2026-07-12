"""Aplicación Textual: el dashboard SOC."""

from __future__ import annotations

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import Footer

from ..models import Alert, Event
from ..pipeline import Pipeline
from .widgets import AlertsTable, EventStream, StatsBar, TopAttackers


class NewEvent(Message):
    def __init__(self, event: Event) -> None:
        super().__init__()
        self.event = event


class NewAlert(Message):
    def __init__(self, alert: Alert) -> None:
        super().__init__()
        self.alert = alert


class SiemApp(App):
    """Dashboard en terminal: stream de eventos, alertas y top de atacantes."""

    TITLE = "MiniSIEM"
    CSS_PATH = "styles.tcss"
    BINDINGS = [
        ("q", "quit", "Salir"),
        ("p", "toggle_pause", "Pausar stream"),
        ("c", "clear_stream", "Limpiar stream"),
    ]

    def __init__(self, pipeline: Pipeline) -> None:
        super().__init__()
        self.pipeline = pipeline

    def compose(self) -> ComposeResult:
        yield StatsBar()
        with Horizontal(id="body"):
            stream = EventStream()
            stream.border_title = "EVENTOS EN VIVO"
            yield stream
            with Vertical(id="sidebar"):
                alerts = AlertsTable()
                alerts.border_title = "ALERTAS"
                yield alerts
                attackers = TopAttackers()
                attackers.border_title = "TOP ATACANTES"
                yield attackers
        yield Footer()

    def on_mount(self) -> None:
        # El pipeline corre en sus propios hilos; post_message es thread-safe.
        self.pipeline.on_event = lambda event: self.post_message(NewEvent(event))
        self.pipeline.on_alert = lambda alert: self.post_message(NewAlert(alert))
        self.pipeline.start()

    def on_unmount(self) -> None:
        self.pipeline.stop()

    def on_new_event(self, message: NewEvent) -> None:
        self.query_one(StatsBar).record_event()
        self.query_one(EventStream).add_event(message.event)
        self.query_one(TopAttackers).record_event(message.event)

    def on_new_alert(self, message: NewAlert) -> None:
        self.query_one(StatsBar).record_alert(message.alert)
        self.query_one(AlertsTable).add_alert(message.alert)
        self.notify(
            message.alert.message,
            title=f"{message.alert.severity.label} · {message.alert.rule}",
            severity="error" if message.alert.severity >= 3 else "warning",
            timeout=6,
        )

    def action_toggle_pause(self) -> None:
        stream = self.query_one(EventStream)
        stream.paused = not stream.paused
        stream.border_title = "EVENTOS EN VIVO [PAUSADO]" if stream.paused else "EVENTOS EN VIVO"

    def action_clear_stream(self) -> None:
        self.query_one(EventStream).clear()
