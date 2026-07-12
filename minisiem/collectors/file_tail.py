"""Collector tipo `tail -f` para ficheros de log locales."""

from __future__ import annotations

import os
import queue

from .base import BaseCollector


class FileTailCollector(BaseCollector):
    """Sigue un fichero de log emitiendo cada línea nueva.

    Empieza al final del fichero (solo eventos nuevos) y detecta la rotación
    típica de logrotate: si el inode cambia o el fichero encoge, reabre.
    """

    POLL_SECONDS = 0.2

    def __init__(self, out_queue: queue.Queue[str], path: str, from_start: bool = False):
        super().__init__(out_queue, name=os.path.basename(path))
        self.path = path
        self.from_start = from_start

    def run(self) -> None:
        handle = None
        inode = None
        try:
            while not self.stopped:
                if handle is None:
                    try:
                        handle = open(self.path, "r", errors="replace")
                        inode = os.fstat(handle.fileno()).st_ino
                        if not self.from_start:
                            handle.seek(0, os.SEEK_END)
                    except OSError:
                        self._stop_event.wait(1.0)
                        continue

                line = handle.readline()
                if line:
                    self.emit(line)
                    continue

                # Sin datos nuevos: comprobar rotación antes de esperar.
                try:
                    stat = os.stat(self.path)
                    rotated = stat.st_ino != inode or stat.st_size < handle.tell()
                except OSError:
                    rotated = True
                if rotated:
                    handle.close()
                    handle = None
                    self.from_start = True  # tras rotar, el fichero nuevo se lee entero
                else:
                    self._stop_event.wait(self.POLL_SECONDS)
        finally:
            if handle is not None:
                handle.close()
