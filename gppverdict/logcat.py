"""Capture logcat during each install, with a filtered excerpt."""
from __future__ import annotations

import subprocess
from pathlib import Path

KEYWORDS = [
    "play protect", "playprotect", "packageverifier", "verifyapps", "verify apps",
    "finsky", "phonesky", "harmful", "packageinstaller", "install_failed",
    "verification", "deprecated_sdk",
]


class LogcatCapture:
    def __init__(self, device, out_path: Path, keep_full: bool = False):
        self.device = device
        self.out_path = out_path
        self.keep_full = keep_full
        self._proc = None
        self._fh = None

    def start(self) -> "LogcatCapture":
        self.device.run(["logcat", "-c"], timeout=30)
        self._fh = open(self.out_path.with_suffix(".full.log"), "wb")
        self._proc = subprocess.Popen(self.device.base + ["logcat", "-v", "threadtime"],
                                      stdout=self._fh, stderr=subprocess.DEVNULL)
        return self

    def stop(self, extra_keywords=()) -> str:
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        if self._fh:
            self._fh.close()
        full = self.out_path.with_suffix(".full.log")
        if not full.exists():
            return ""
        kws = [k.lower() for k in KEYWORDS + [k for k in extra_keywords if k]]
        lines = full.read_bytes().decode("utf-8", errors="replace").splitlines()
        kept = [l for l in lines if any(k in l.lower() for k in kws)]
        excerpt = "\n".join(kept)
        self.out_path.write_text(excerpt, encoding="utf-8")
        if not self.keep_full:
            full.unlink(missing_ok=True)
        return excerpt
