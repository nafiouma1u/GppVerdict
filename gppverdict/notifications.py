"""Capture Play Protect notifications via `dumpsys notification`.

Besides the on-screen dialog caught by the watcher, Play Protect may post a
notification ("Harmful app blocked", "App scanned", etc.). We snapshot the
notifications before the install, again after, and return the new ones that come from
Play Protect (GMS / Play Store)."""
from __future__ import annotations

import re

# Packages that post Play Protect notifications.
PP_PACKAGES = {"com.google.android.gms", "com.android.vending", "com.google.android.odad"}

_REC_RE = re.compile(r"NotificationRecord\(0x[0-9a-f]+:\s+pkg=(\S+).*?\bid=(-?\d+)\b.*?\btag=(\S+?)\b.*?\bkey=([^:]+):")
_STR_RE = re.compile(r"(android\.\w+)=String \((.*)\)")
_WHEN_RE = re.compile(r"\bwhen=(\d+)")
_ACTION_RE = re.compile(r'\[\d+\]\s+"([^"]*)"')


def _parse(dump: str) -> list[dict]:
    """Split the dumpsys output into notification records."""
    records = []
    cur = None
    in_actions = in_extras = False
    for line in dump.splitlines():
        m = _REC_RE.search(line)
        if m:
            if cur:
                records.append(cur)
            pkg, nid, tag, key = m.groups()
            cur = {"pkg": pkg, "id": nid, "tag": tag, "key": key.strip(),
                   "when": None, "title": None, "text": None, "sub_text": None,
                   "big_text": None, "actions": [], "lines": []}
            in_actions = in_extras = False
            continue
        if cur is None:
            continue
        stripped = line.strip()
        w = _WHEN_RE.search(line)
        if w and cur["when"] is None:
            cur["when"] = int(w.group(1))
        if stripped.startswith("actions={"):
            in_actions = True
        elif in_actions:
            a = _ACTION_RE.search(stripped)
            if a:
                cur["actions"].append(a.group(1))
            if stripped == "}":
                in_actions = False
        if stripped.startswith("extras={"):
            in_extras = True
        elif in_extras and stripped == "}":
            in_extras = False
        s = _STR_RE.search(line)
        if s:
            field = {"android.title": "title", "android.text": "text",
                     "android.subText": "sub_text", "android.bigText": "big_text"}.get(s.group(1))
            val = s.group(2)
            if field and val != "null":
                cur[field] = val
            if s.group(1).startswith("android.") and val and val != "null":
                cur["lines"].append(val)
    if cur:
        records.append(cur)
    return records


class NotificationCapture:
    """Compare the notification state before/after installation."""

    def __init__(self, device):
        self.device = device
        self.before_keys: set[str] = set()

    def _dump(self) -> str:
        return self.device.shell("dumpsys notification --noredact", timeout=40)

    def snapshot(self) -> "NotificationCapture":
        self.before_keys = {r["key"] for r in _parse(self._dump())}
        return self

    def collect(self, package: str | None = None) -> list[dict]:
        """Return the Play Protect notifications that are new since the snapshot.

        Also keep those whose text mentions the tested package (in case it was already
        there but got updated)."""
        out = []
        for r in _parse(self._dump()):
            new = r["key"] not in self.before_keys
            from_pp = r["pkg"] in PP_PACKAGES
            mentions = package and any(package in (v or "") for v in r["lines"])
            if from_pp and (new or mentions):
                r["new"] = new
                out.append(r)
        return out
