from minisiem.models import EventType
from minisiem.parsers import parse_line


def test_ssh_failed_password():
    line = "Jul 12 01:15:30 web-01 sshd[1234]: Failed password for root from 203.0.113.45 port 51023 ssh2"
    event = parse_line(line)
    assert event is not None
    assert event.event_type == EventType.SSH_FAILED_LOGIN
    assert event.host == "web-01"
    assert event.source == "sshd"
    assert event.user == "root"
    assert event.src_ip == "203.0.113.45"


def test_ssh_failed_password_invalid_user():
    line = "Jul 12 01:15:30 db-01 sshd[999]: Failed password for invalid user admin from 198.51.100.7 port 40000 ssh2"
    event = parse_line(line)
    assert event.event_type == EventType.SSH_FAILED_LOGIN
    assert event.user == "admin"
    assert event.src_ip == "198.51.100.7"


def test_ssh_accepted_publickey():
    line = "Jul 12 09:00:01 bastion sshd[42]: Accepted publickey for ana from 10.20.30.5 port 55000 ssh2"
    event = parse_line(line)
    assert event.event_type == EventType.SSH_LOGIN_SUCCESS
    assert event.user == "ana"
    assert event.src_ip == "10.20.30.5"


def test_ssh_invalid_user():
    line = "Jul 12 03:00:00 web-01 sshd[77]: Invalid user oracle from 192.0.2.9 port 33000"
    event = parse_line(line)
    assert event.event_type == EventType.SSH_INVALID_USER
    assert event.user == "oracle"
    assert event.src_ip == "192.0.2.9"


def test_sudo_auth_failure_pam():
    line = (
        "Jul 12 10:00:00 db-01 sudo: pam_unix(sudo:auth): authentication failure; "
        "logname=carlos uid=1000 euid=0 tty=/dev/pts/1 ruser=carlos rhost= user=carlos"
    )
    event = parse_line(line)
    assert event.event_type == EventType.SUDO_AUTH_FAILURE
    assert event.user == "carlos"


def test_sudo_incorrect_attempts():
    line = (
        "Jul 12 10:00:10 db-01 sudo: carlos : 3 incorrect password attempts ; "
        "TTY=pts/1 ; PWD=/home/carlos ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    )
    event = parse_line(line)
    assert event.event_type == EventType.SUDO_AUTH_FAILURE
    assert event.user == "carlos"


def test_sudo_command():
    line = (
        "Jul 12 11:00:00 web-01 sudo: ana : TTY=pts/0 ; PWD=/home/ana ; "
        "USER=root ; COMMAND=/usr/bin/systemctl restart nginx"
    )
    event = parse_line(line)
    assert event.event_type == EventType.SUDO_COMMAND
    assert event.user == "ana"


def test_useradd_new_user():
    line = (
        "Jul 12 12:00:00 web-01 useradd[500]: new user: name=backdoor, UID=1500, "
        "GID=1500, home=/home/backdoor, shell=/bin/bash, from=/dev/pts/2"
    )
    event = parse_line(line)
    assert event.event_type == EventType.USER_CREATED
    assert event.user == "backdoor"


def test_iso_timestamp_header():
    line = "2026-07-12T01:15:30.123456+02:00 web-01 sshd[1]: Failed password for root from 203.0.113.1 port 1 ssh2"
    event = parse_line(line)
    assert event is not None
    assert event.event_type == EventType.SSH_FAILED_LOGIN


def test_unknown_process_is_other():
    line = "Jul 12 01:00:00 web-01 kernel: usb 1-1: new high-speed USB device"
    event = parse_line(line)
    assert event is not None
    assert event.event_type == EventType.OTHER


def test_garbage_line_returns_none():
    assert parse_line("esto no es una línea de syslog") is None
    assert parse_line("") is None
