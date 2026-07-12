"""Punto de entrada: `python -m minisiem [--demo | --log-file PATH ...]`."""

from __future__ import annotations

import argparse
import os
import sys

from .collectors import FileTailCollector, SimulatorCollector
from .detection import DetectionEngine
from .pipeline import Pipeline
from .storage import Storage
from .tui import SiemApp

DEFAULT_LOGS = ("/var/log/auth.log", "/var/log/syslog")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="minisiem",
        description="MiniSIEM: monitorización y detección sobre logs de Linux con dashboard TUI.",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="usar el simulador de eventos en lugar de logs reales (ideal para probarlo)",
    )
    parser.add_argument(
        "--log-file",
        action="append",
        metavar="PATH",
        help="fichero de log a seguir (repetible); por defecto auth.log y syslog",
    )
    parser.add_argument(
        "--from-start",
        action="store_true",
        help="leer los ficheros de log desde el principio en vez de solo lo nuevo",
    )
    parser.add_argument(
        "--db",
        default="minisiem.db",
        metavar="PATH",
        help="ruta de la base de datos SQLite (por defecto ./minisiem.db)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    storage = Storage(args.db)
    pipeline = Pipeline(storage, DetectionEngine())

    if args.demo:
        pipeline.add_collector(SimulatorCollector(pipeline.queue))
    else:
        paths = args.log_file or [p for p in DEFAULT_LOGS if os.path.exists(p)]
        readable = [p for p in paths if os.access(p, os.R_OK)]
        denied = [p for p in paths if p not in readable]
        if denied:
            print(f"aviso: sin permiso de lectura sobre {', '.join(denied)}", file=sys.stderr)
        if not readable:
            print(
                "error: ningún fichero de log legible.\n"
                "Prueba con sudo, con --log-file PATH, o lanza el modo demo:\n"
                "    python -m minisiem --demo",
                file=sys.stderr,
            )
            return 1
        for path in readable:
            pipeline.add_collector(
                FileTailCollector(pipeline.queue, path, from_start=args.from_start)
            )

    SiemApp(pipeline).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
