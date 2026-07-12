from minisiem.models import Alert, Event, EventType, Severity
from minisiem.storage import Storage


def make_storage():
    return Storage(":memory:")


def test_add_and_count_events():
    storage = make_storage()
    event = Event(
        timestamp=100.0,
        host="web-01",
        source="sshd",
        event_type=EventType.SSH_FAILED_LOGIN,
        message="Failed password for root from 203.0.113.1",
        user="root",
        src_ip="203.0.113.1",
    )
    storage.add_event(event)
    storage.add_event(event)
    assert storage.event_count() == 2


def test_add_and_read_alerts():
    storage = make_storage()
    storage.add_alert(
        Alert(rule="ssh_brute_force", severity=Severity.HIGH, entity="203.0.113.1",
              message="fuerza bruta", timestamp=50.0)
    )
    storage.add_alert(
        Alert(rule="root_ssh_login", severity=Severity.CRITICAL, entity="203.0.113.2",
              message="root login", timestamp=60.0)
    )
    alerts = storage.recent_alerts()
    assert storage.alert_count() == 2
    assert alerts[0].rule == "root_ssh_login"  # más reciente primero
    assert alerts[0].severity == Severity.CRITICAL
    assert alerts[1].entity == "203.0.113.1"


def test_top_attackers_counts_only_hostile_events():
    storage = make_storage()

    def add(event_type, ip, n):
        for _ in range(n):
            storage.add_event(
                Event(timestamp=1.0, host="h", source="sshd", event_type=event_type,
                      message="m", user="u", src_ip=ip)
            )

    add(EventType.SSH_FAILED_LOGIN, "203.0.113.1", 3)
    add(EventType.SSH_INVALID_USER, "198.51.100.2", 5)
    add(EventType.SSH_LOGIN_SUCCESS, "10.0.0.1", 10)  # legítimo: no cuenta

    top = storage.top_attackers()
    assert top == [("198.51.100.2", 5), ("203.0.113.1", 3)]
