from minisiem.detection import DetectionEngine
from minisiem.detection.rules import (
    InvalidUserSprayRule,
    NewUserCreatedRule,
    RootLoginRule,
    SSHBruteForceRule,
    SSHSuccessAfterFailuresRule,
    SudoFailureRule,
)
from minisiem.models import Event, EventType, Severity


def make_event(event_type, ts=0.0, user="root", src_ip="203.0.113.1"):
    return Event(
        timestamp=ts,
        host="web-01",
        source="sshd",
        event_type=event_type,
        message="línea sintética",
        user=user,
        src_ip=src_ip,
    )


class TestSSHBruteForce:
    def test_fires_at_threshold_within_window(self):
        rule = SSHBruteForceRule()
        alerts = [
            rule.check(make_event(EventType.SSH_FAILED_LOGIN, ts=float(i)))
            for i in range(5)
        ]
        assert alerts[:4] == [None, None, None, None]
        assert alerts[4] is not None
        assert alerts[4].severity == Severity.HIGH
        assert alerts[4].entity == "203.0.113.1"

    def test_does_not_fire_outside_window(self):
        rule = SSHBruteForceRule()
        for i in range(5):
            alert = rule.check(make_event(EventType.SSH_FAILED_LOGIN, ts=i * 30.0))
            assert alert is None  # 30s entre fallos: nunca hay 5 vivos en 60s

    def test_different_ips_do_not_mix(self):
        rule = SSHBruteForceRule()
        for i in range(4):
            rule.check(make_event(EventType.SSH_FAILED_LOGIN, ts=float(i), src_ip="203.0.113.1"))
        alert = rule.check(make_event(EventType.SSH_FAILED_LOGIN, ts=4.0, src_ip="198.51.100.9"))
        assert alert is None


class TestSSHSuccessAfterFailures:
    def test_success_after_failures_is_critical(self):
        rule = SSHSuccessAfterFailuresRule()
        for i in range(3):
            assert rule.check(make_event(EventType.SSH_FAILED_LOGIN, ts=float(i))) is None
        alert = rule.check(make_event(EventType.SSH_LOGIN_SUCCESS, ts=4.0))
        assert alert is not None
        assert alert.severity == Severity.CRITICAL

    def test_clean_success_does_not_fire(self):
        rule = SSHSuccessAfterFailuresRule()
        assert rule.check(make_event(EventType.SSH_LOGIN_SUCCESS, ts=0.0)) is None


class TestRootLogin:
    def test_root_login_fires(self):
        alert = RootLoginRule().check(make_event(EventType.SSH_LOGIN_SUCCESS, user="root"))
        assert alert is not None
        assert alert.severity == Severity.HIGH

    def test_normal_user_does_not_fire(self):
        assert RootLoginRule().check(make_event(EventType.SSH_LOGIN_SUCCESS, user="ana")) is None


class TestInvalidUserSpray:
    def test_fires_at_threshold(self):
        rule = InvalidUserSprayRule()
        alerts = [
            rule.check(make_event(EventType.SSH_INVALID_USER, ts=float(i)))
            for i in range(5)
        ]
        assert alerts[4] is not None
        assert alerts[4].severity == Severity.MEDIUM


class TestSudoFailure:
    def test_fires_at_threshold_per_user(self):
        rule = SudoFailureRule()
        for i in range(2):
            assert (
                rule.check(make_event(EventType.SUDO_AUTH_FAILURE, ts=float(i), user="carlos"))
                is None
            )
        alert = rule.check(make_event(EventType.SUDO_AUTH_FAILURE, ts=2.0, user="carlos"))
        assert alert is not None
        assert alert.entity == "carlos"


class TestNewUserCreated:
    def test_fires_immediately(self):
        alert = NewUserCreatedRule().check(make_event(EventType.USER_CREATED, user="backdoor"))
        assert alert is not None
        assert "backdoor" in alert.message


class TestEngine:
    def test_cooldown_suppresses_duplicates(self):
        engine = DetectionEngine(rules=[RootLoginRule()], cooldown_seconds=60.0)
        first = engine.process(make_event(EventType.SSH_LOGIN_SUCCESS, ts=0.0, user="root"))
        repeat = engine.process(make_event(EventType.SSH_LOGIN_SUCCESS, ts=10.0, user="root"))
        later = engine.process(make_event(EventType.SSH_LOGIN_SUCCESS, ts=100.0, user="root"))
        assert len(first) == 1
        assert repeat == []
        assert len(later) == 1

    def test_default_rules_end_to_end_brute_force(self):
        engine = DetectionEngine()
        fired = []
        for i in range(6):
            fired += engine.process(make_event(EventType.SSH_FAILED_LOGIN, ts=float(i)))
        fired += engine.process(
            make_event(EventType.SSH_LOGIN_SUCCESS, ts=7.0, user="root")
        )
        rules_fired = {alert.rule for alert in fired}
        assert "ssh_brute_force" in rules_fired
        assert "ssh_success_after_failures" in rules_fired
        assert "root_ssh_login" in rules_fired
