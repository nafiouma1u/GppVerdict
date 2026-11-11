"""Categorize alerts and the final outcome. The rules are keyword lists.

The keywords are intentionally BILINGUAL (English + French): they are matched against
the Play Protect dialog/notification text as rendered on the device, so they must
include every language the test phone's UI may use. Add your own locale's wording to
the lists below after looking at the raw `texts_json` your run captures.
"""
from __future__ import annotations

from .watcher import norm

CATEGORY_RULES = [
    ("harmful", ["harmful", "dangereuse", "malveillant", "malware"]),
    ("old_target_sdk", ["older version of android", "ancienne version d'android",
                        "version antérieure d'android", "version plus ancienne d'android"]),
    ("scan_prompt", ["security check", "scan app", "contrôle de sécurité",
                     "analyser l'application", "analyse de sécurité"]),
    ("unverified_developer", ["unknown developer", "développeur inconnu", "unverified",
                              "non vérifié"]),
    ("no_problem_found", ["no problems found", "aucun problème"]),
    ("unsafe", ["unsafe", "non sécurisée", "at risk", "risque"]),
]
PRIORITY = ["harmful", "old_target_sdk", "unsafe", "unverified_developer", "scan_prompt",
            "no_problem_found", "other", "progress"]


def categorize_text(text: str) -> str:
    text = norm(text)
    for cat, kws in CATEGORY_RULES:
        if any(k in text for k in kws):
            return cat
    return "other"


def categorize(alert: dict) -> str:
    if not alert.get("buttons"):
        return "progress"
    return categorize_text(" ".join(alert.get("texts", [])))


def is_blocked(alert: dict) -> bool:
    t = norm(alert.get("title") or "")
    return "blocked" in t or "bloqu" in t


def primary_category(alerts: list[dict]) -> str | None:
    cats = {a["category"] for a in alerts}
    for c in PRIORITY:
        if c in cats:
            return c
    return None


def outcome(alerts: list[dict], install: dict | None) -> str:
    real = [a for a in alerts if a["category"] != "progress"]
    if install is None:
        return "error"
    if install["timed_out"]:
        return "timeout_after_alert" if real else "timeout"
    if install["success"]:
        return "installed_after_alert" if real else "installed_no_alert"
    if real:
        return "blocked_by_play_protect"
    return "install_failed"
