"""Run `adb install` in a thread: the command stays blocked while the Play Protect
dialog is shown, and the watcher handles it in the meantime."""
from __future__ import annotations

import re
import subprocess
import threading
import time

FAILURE_RE = re.compile(r"Failure \[([A-Z0-9_]+)(?::\s*([^\]]*))?\]")


class AsyncInstall:
    def __init__(self, device, apk_path, flags=None, timeout: int = 120):
        self.device = device
        self.apk_path = apk_path
        self.flags = list(flags or [])
        self.timeout = timeout
        self.result: dict | None = None
        self.finished_at: float | None = None
        self._done = threading.Event()

    def start(self) -> "AsyncInstall":
        threading.Thread(target=self._run, daemon=True).start()
        return self

    def _run(self) -> None:
        cmd = self.device.base + ["install"] + self.flags + [str(self.apk_path)]
        t0 = time.time()
        timed_out = False
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, encoding="utf-8", errors="replace")
            try:
                out, err = p.communicate(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                p.kill()
                out, err = p.communicate()
                timed_out = True
            rc = p.returncode
        except Exception as e:  # noqa: BLE001
            out, err, rc = "", str(e), -1
        text = f"{out or ''}\n{err or ''}".strip()
        m = FAILURE_RE.search(text)
        self.result = {
            "returncode": rc,
            "success": "Success" in (out or "") and not timed_out,
            "failure_code": m.group(1) if m else None,
            "output": text[-4000:],
            "timed_out": timed_out,
            "duration_s": round(time.time() - t0, 2),
        }
        self.finished_at = time.time()
        self._done.set()

    @property
    def done(self) -> bool:
        return self._done.is_set()

    def wait(self, timeout: float | None = None) -> dict | None:
        self._done.wait(timeout)
        return self.result
