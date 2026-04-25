"""
Simple JSON-lines logger. All test events must be auditable (project spec).
"""
import os
import json
import time
import threading
from collections import deque


class TestLogger:
    def __init__(self, log_dir, max_memory=2000):
        os.makedirs(log_dir, exist_ok=True)
        self.path = os.path.join(log_dir, "testing.jsonl")
        self.buf = deque(maxlen=max_memory)
        self._lock = threading.Lock()

    def info(self, category, message):
        self._write("INFO", category, message)

    def warn(self, category, message):
        self._write("WARN", category, message)

    def error(self, category, message):
        self._write("ERROR", category, message)

    def _write(self, level, category, message):
        entry = {
            "ts": time.time(),
            "level": level,
            "category": category,
            "message": message,
        }
        with self._lock:
            self.buf.append(entry)
            try:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            except Exception:
                pass

    def tail(self, n=200):
        with self._lock:
            return list(self.buf)[-n:]
