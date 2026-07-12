"""Simulador de eventos para el modo demo.

Genera líneas con formato auth.log real: ruido normal de fondo (logins
legítimos, sudo, cron) y, cada cierto tiempo, un escenario de ataque completo
(fuerza bruta SSH, enumeración de usuarios, abuso de sudo, persistencia).
Todo el tráfico de ataque usa rangos de IP reservados para documentación
(RFC 5737), así que nada apunta a direcciones reales.
"""

from __future__ import annotations

import queue
import random
import time

from .base import BaseCollector

_HOSTS = ("web-01", "db-01", "bastion")
_USERS = ("ana", "carlos", "deploy", "lucia", "marta")
_INVALID_USERS = ("admin", "test", "oracle", "postgres", "guest", "ftpuser", "pi", "user")
_SUDO_COMMANDS = (
    "/usr/bin/systemctl restart nginx",
    "/usr/bin/apt update",
    "/usr/bin/tail -f /var/log/syslog",
    "/bin/cat /etc/shadow",
)


def _attacker_ip() -> str:
    prefix = random.choice(("203.0.113", "198.51.100", "192.0.2"))
    return f"{prefix}.{random.randint(1, 254)}"


def _office_ip() -> str:
    return f"10.20.30.{random.randint(2, 60)}"


def _stamp() -> str:
    return time.strftime("%b %e %H:%M:%S")


def _pid() -> int:
    return random.randint(800, 65000)


class SimulatorCollector(BaseCollector):
    """Emite ruido de fondo continuo y lanza un escenario de ataque periódicamente."""

    NOISE_DELAY = (0.4, 1.6)  # segundos entre eventos de fondo
    SCENARIO_EVERY = (10.0, 25.0)  # segundos entre ataques

    def __init__(self, out_queue: queue.Queue[str], seed: int | None = None) -> None:
        super().__init__(out_queue, name="simulator")
        if seed is not None:
            random.seed(seed)

    def run(self) -> None:
        next_attack = time.monotonic() + random.uniform(3.0, 8.0)
        while not self.stopped:
            if time.monotonic() >= next_attack:
                self._run_scenario()
                next_attack = time.monotonic() + random.uniform(*self.SCENARIO_EVERY)
            else:
                self.emit(self._noise_line())
                self._stop_event.wait(random.uniform(*self.NOISE_DELAY))

    # --- ruido legítimo -------------------------------------------------

    def _noise_line(self) -> str:
        host = random.choice(_HOSTS)
        user = random.choice(_USERS)
        roll = random.random()
        if roll < 0.35:
            return (
                f"{_stamp()} {host} sshd[{_pid()}]: Accepted publickey for {user} "
                f"from {_office_ip()} port {random.randint(40000, 65000)} ssh2"
            )
        if roll < 0.55:
            cmd = random.choice(_SUDO_COMMANDS[:3])
            return (
                f"{_stamp()} {host} sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; "
                f"USER=root ; COMMAND={cmd}"
            )
        if roll < 0.75:
            return (
                f"{_stamp()} {host} CRON[{_pid()}]: (root) CMD "
                f"(command -v debian-sa1 > /dev/null && debian-sa1 1 1)"
            )
        if roll < 0.9:
            return (
                f"{_stamp()} {host} systemd[1]: Started Session {random.randint(100, 999)} "
                f"of User {user}."
            )
        return (
            f"{_stamp()} {host} sshd[{_pid()}]: Failed password for {user} "
            f"from {_office_ip()} port {random.randint(40000, 65000)} ssh2"
        )

    # --- escenarios de ataque -------------------------------------------

    def _run_scenario(self) -> None:
        scenario = random.choice(
            (
                self._brute_force,
                self._brute_force,  # el más vistoso, con más peso
                self._user_enumeration,
                self._sudo_abuse,
                self._persistence,
            )
        )
        scenario()

    def _pace(self, low: float = 0.15, high: float = 0.6) -> None:
        self._stop_event.wait(random.uniform(low, high))

    def _brute_force(self) -> None:
        """Ráfaga de fallos de login; a veces el atacante acaba entrando."""
        ip = _attacker_ip()
        host = random.choice(_HOSTS)
        target = random.choice(("root", random.choice(_USERS)))
        port = random.randint(30000, 60000)
        for _ in range(random.randint(6, 12)):
            if self.stopped:
                return
            self.emit(
                f"{_stamp()} {host} sshd[{_pid()}]: Failed password for {target} "
                f"from {ip} port {port} ssh2"
            )
            self._pace()
        if random.random() < 0.4:
            self.emit(
                f"{_stamp()} {host} sshd[{_pid()}]: Accepted password for {target} "
                f"from {ip} port {port} ssh2"
            )

    def _user_enumeration(self) -> None:
        ip = _attacker_ip()
        host = random.choice(_HOSTS)
        for user in random.sample(_INVALID_USERS, k=random.randint(5, 8)):
            if self.stopped:
                return
            pid = _pid()
            port = random.randint(30000, 60000)
            self.emit(f"{_stamp()} {host} sshd[{pid}]: Invalid user {user} from {ip} port {port}")
            self.emit(
                f"{_stamp()} {host} sshd[{pid}]: Failed password for invalid user {user} "
                f"from {ip} port {port} ssh2"
            )
            self._pace()

    def _sudo_abuse(self) -> None:
        host = random.choice(_HOSTS)
        user = random.choice(_USERS)
        for _ in range(3):
            if self.stopped:
                return
            self.emit(
                f"{_stamp()} {host} sudo: pam_unix(sudo:auth): authentication failure; "
                f"logname={user} uid=1000 euid=0 tty=/dev/pts/1 ruser={user} rhost= user={user}"
            )
            self._pace(0.3, 0.9)
        self.emit(
            f"{_stamp()} {host} sudo: {user} : 3 incorrect password attempts ; "
            f"TTY=pts/1 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/cat /etc/shadow"
        )

    def _persistence(self) -> None:
        host = random.choice(_HOSTS)
        name = random.choice(("backup2", "sysupd", "svc-mon", "dbadmin2"))
        uid = random.randint(1005, 1900)
        self.emit(
            f"{_stamp()} {host} useradd[{_pid()}]: new user: name={name}, UID={uid}, "
            f"GID={uid}, home=/home/{name}, shell=/bin/bash, from=/dev/pts/2"
        )
