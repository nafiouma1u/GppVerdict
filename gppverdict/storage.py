"""CSV storage — no database.

The CSV files ARE the source of truth. Each processed APK appends one row to
``results.csv`` (plus one row per Play Protect dialog to ``alerts.csv`` and one
per notification to ``notifications.csv``), and run metadata goes to ``runs.csv``.
Rows are flushed after every APK, so the files are always complete even if the run
is interrupted; a resumed run reads ``results.csv`` to skip what is already done.

``result_id`` links alerts/notifications back to their result row; ``sha256`` is
duplicated into every file so each one is usable on its own. Bulky or
machine-specific fields (the local APK path, the raw install output, the 20k-char
logcat excerpt) are deliberately NOT written to CSV — the logcat is kept as a file
under ``logcat/`` and referenced by ``logcat_path``.
"""
from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

RESULT_COLS = [
    "result_id", "run_id", "sha256", "file_name", "package", "version_name",
    "version_code", "app_label", "min_sdk", "target_sdk", "permissions_json",
    "static_error", "outcome", "primary_category", "alert_count", "install_success",
    "install_failure_code", "install_duration_s", "installed_packages_json",
    "uninstalled", "logcat_path", "error", "created_at", "vt_detection", "vt_bucket",
    "catalog_year", "market", "notification_count", "net_online",
]
ALERT_COLS = [
    "result_id", "sha256", "idx", "dialog_package", "title", "app_label", "body",
    "category", "blocked", "buttons_json", "texts_json", "action", "screenshot_path",
    "detected_after_s",
]
NOTIF_COLS = [
    "result_id", "sha256", "idx", "source_package", "title", "text", "sub_text",
    "big_text", "category", "blocked", "actions_json", "is_new", "posted_when", "key",
    "screenshot_path",
]
RUN_COLS = ["run_id", "started_at", "ended_at", "device_json", "args_json"]

# Outcomes that do not count as "processed" for --resume (they are retried).
_UNFINISHED = ("error", "timeout")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read_rows(path: Path) -> list[dict]:
    """Read a CSV written by this module into a list of dicts (empty if absent)."""
    if not path.exists():
        return []
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def latest_by_sha(rows: list[dict]) -> dict[str, dict]:
    """Keep the most recent row per sha256 (highest result_id). A resumed/retested
    run may append the same sha more than once; this de-duplicates to the last try."""
    best: dict[str, dict] = {}
    for r in rows:
        sha = r.get("sha256")
        if not sha:
            continue
        try:
            rid = int(r.get("result_id") or 0)
        except ValueError:
            rid = 0
        prev = best.get(sha)
        if prev is None or rid >= int(prev.get("result_id") or 0):
            best[sha] = r
    return best


class Storage:
    def __init__(self, out_dir: Path):
        self.dir = Path(out_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.results_csv = self.dir / "results.csv"
        self.alerts_csv = self.dir / "alerts.csv"
        self.notifications_csv = self.dir / "notifications.csv"
        self.runs_csv = self.dir / "runs.csv"
        for path, cols in ((self.results_csv, RESULT_COLS), (self.alerts_csv, ALERT_COLS),
                           (self.notifications_csv, NOTIF_COLS), (self.runs_csv, RUN_COLS)):
            if not path.exists():
                self._write_header(path, cols)
        self._next_result_id = self._max_int(self.results_csv, "result_id") + 1
        self._next_run_id = self._max_int(self.runs_csv, "run_id") + 1

    @staticmethod
    def _write_header(path: Path, cols: list[str]) -> None:
        with open(path, "w", newline="", encoding="utf-8-sig") as f:  # utf-8-sig: Excel
            csv.writer(f).writerow(cols)

    @staticmethod
    def _max_int(path: Path, col: str) -> int:
        m = 0
        for r in _read_rows(path):
            try:
                m = max(m, int(r.get(col) or 0))
            except ValueError:
                pass
        return m

    @staticmethod
    def _append(path: Path, cols: list[str], row: dict) -> None:
        with open(path, "a", newline="", encoding="utf-8-sig") as f:
            csv.writer(f).writerow([row.get(c, "") for c in cols])

    def start_run(self, device: dict, args: dict) -> int:
        run_id = self._next_run_id
        self._next_run_id += 1
        safe_args = dict(args)
        if safe_args.get("apikey"):  # never persist a key passed on the command line
            safe_args["apikey"] = "***"
        self._append(self.runs_csv, RUN_COLS, {
            "run_id": run_id, "started_at": now(), "ended_at": "",
            "device_json": json.dumps(device, ensure_ascii=False),
            "args_json": json.dumps(safe_args, ensure_ascii=False, default=str)})
        return run_id

    def end_run(self, run_id: int) -> None:
        rows = _read_rows(self.runs_csv)
        for r in rows:
            if r.get("run_id") == str(run_id):
                r["ended_at"] = now()
        self._write_header(self.runs_csv, RUN_COLS)
        with open(self.runs_csv, "a", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            for r in rows:
                w.writerow([r.get(c, "") for c in RUN_COLS])

    def processed_hashes(self) -> set[str]:
        return {r["sha256"] for r in _read_rows(self.results_csv)
                if r.get("sha256") and r.get("outcome") not in _UNFINISHED}

    def results(self) -> list[dict]:
        return _read_rows(self.results_csv)

    def save(self, run_id: int, rec: dict, alerts: list[dict],
             notifications: list[dict] | None = None) -> int:
        inst = rec.get("install") or {}
        notifications = notifications or []
        sha = rec["sha256"]
        rid = self._next_result_id
        self._next_result_id += 1
        self._append(self.results_csv, RESULT_COLS, {
            "result_id": rid, "run_id": run_id, "sha256": sha,
            "file_name": rec.get("file_name"), "package": rec.get("package"),
            "version_name": _s(rec.get("version_name")), "version_code": _s(rec.get("version_code")),
            "app_label": rec.get("app_label"), "min_sdk": _s(rec.get("min_sdk")),
            "target_sdk": _s(rec.get("target_sdk")),
            "permissions_json": json.dumps(rec.get("permissions", [])),
            "static_error": rec.get("static_error"), "outcome": rec.get("outcome"),
            "primary_category": rec.get("primary_category"), "alert_count": len(alerts),
            "install_success": int(bool(inst.get("success"))),
            "install_failure_code": inst.get("failure_code"),
            "install_duration_s": inst.get("duration_s"),
            "installed_packages_json": json.dumps(rec.get("installed_packages", [])),
            "uninstalled": int(bool(rec.get("uninstalled"))),
            "logcat_path": rec.get("logcat_path"), "error": rec.get("error"),
            "created_at": now(), "vt_detection": rec.get("vt_detection"),
            "vt_bucket": rec.get("vt_bucket"), "catalog_year": rec.get("catalog_year"),
            "market": rec.get("market"), "notification_count": len(notifications),
            "net_online": rec.get("net_online")})
        for i, a in enumerate(alerts, 1):
            self._append(self.alerts_csv, ALERT_COLS, {
                "result_id": rid, "sha256": sha, "idx": i,
                "dialog_package": a.get("dialog_package"), "title": a.get("title"),
                "app_label": a.get("app_label"), "body": a.get("body"),
                "category": a.get("category"), "blocked": int(bool(a.get("blocked"))),
                "buttons_json": json.dumps([b["label"] for b in a.get("buttons", [])],
                                           ensure_ascii=False),
                "texts_json": json.dumps(a.get("texts", []), ensure_ascii=False),
                "action": a.get("action"), "screenshot_path": a.get("screenshot"),
                "detected_after_s": a.get("detected_after_s")})
        for i, n in enumerate(notifications, 1):
            self._append(self.notifications_csv, NOTIF_COLS, {
                "result_id": rid, "sha256": sha, "idx": i, "source_package": n.get("pkg"),
                "title": n.get("title"), "text": n.get("text"), "sub_text": n.get("sub_text"),
                "big_text": n.get("big_text"), "category": n.get("category"),
                "blocked": int(bool(n.get("blocked"))),
                "actions_json": json.dumps(n.get("actions", []), ensure_ascii=False),
                "is_new": int(bool(n.get("new"))), "posted_when": n.get("when"),
                "key": n.get("key"), "screenshot_path": n.get("screenshot")})
        return rid

    def paths(self) -> list[Path]:
        return [self.results_csv, self.alerts_csv, self.notifications_csv]


def _s(v):
    return None if v is None else str(v)
