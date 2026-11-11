"""Detect and extract Play Protect dialogs from the UI tree (uiautomator2).

Safety rule: the tool NEVER clicks "Install anyway" or "Install without scanning".
It dismisses the dialog or, if allowed, starts the scan.
"""
from __future__ import annotations

import hashlib
import re
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path

PP_PACKAGES = {"com.google.android.gms", "com.android.vending"}

# Delay beyond which a uiautomator2 call is considered stuck (dead agent, phone
# offline…). We give up on the call instead of freezing the whole run.
UI_CALL_TIMEOUT = 20.0


class TimeoutExpired(Exception):
    pass


def call_timeout(fn, timeout: float, *args, **kwargs):
    """Run fn(*args) in a thread; raise TimeoutExpired beyond `timeout`.

    The thread left stuck (on a dead socket) is a daemon: it stops neither the loop
    from continuing nor the process from exiting."""
    box: dict = {}

    def run():
        try:
            box["r"] = fn(*args, **kwargs)
        except BaseException as e:  # noqa: BLE001
            box["e"] = e

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise TimeoutExpired(f"{getattr(fn, '__name__', fn)} > {timeout}s")
    if "e" in box:
        raise box["e"]
    return box.get("r")

# Button labels matched by exact equality (lower-cased, apostrophes normalized).
# These lists are intentionally BILINGUAL (English + French): they are matched against
# the button text as rendered on the device, so they must cover every language the test
# phone's UI may use. Add your own locale's labels here.
DISMISS_LABELS = [
    "got it", "don't install", "do not install", "ok", "not now", "cancel", "close", "done",
    "don't send", "j'ai compris", "compris", "ne pas installer", "pas maintenant",
    "annuler", "fermer", "terminé", "ne pas envoyer",
]
SCAN_LABELS = ["scan app", "send", "scan", "analyser l'application", "analyser", "envoyer"]
NEVER_CLICK = [
    "install anyway", "install without scanning", "more details",
    "installer quand même", "installer malgré tout", "installer sans analyser", "plus de détails",
]
KNOWN_LABELS = set(DISMISS_LABELS + SCAN_LABELS + NEVER_CLICK + ["learn more", "en savoir plus"])

_BOUNDS_RE = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")


def norm(s: str) -> str:
    return (s or "").replace("\u2019", "'").replace("\u00a0", " ").strip().lower()


def read_nodes(d) -> list[dict]:
    xml = call_timeout(d.dump_hierarchy, UI_CALL_TIMEOUT, compressed=False)
    root = ET.fromstring(xml.encode("utf-8") if isinstance(xml, str) else xml)
    nodes = []
    for n in root.iter("node"):
        nodes.append({
            "text": n.get("text", "") or "",
            "desc": n.get("content-desc", "") or "",
            "pkg": n.get("package", "") or "",
            "cls": n.get("class", "") or "",
            "clickable": n.get("clickable") == "true",
            "bounds": n.get("bounds", "") or "",
        })
    return nodes


def _center(bounds: str):
    m = _BOUNDS_RE.match(bounds)
    if not m:
        return None
    x1, y1, x2, y2 = map(int, m.groups())
    return (x1 + x2) // 2, (y1 + y2) // 2


def find_alert(nodes: list[dict]) -> dict | None:
    """Return a description of the Play Protect dialog shown, or None."""
    anchor = None
    for n in nodes:
        label = norm(f"{n['text']} {n['desc']}")
        if "play protect" in label and (n["pkg"] in PP_PACKAGES or "google play protect" in label):
            anchor = n
            break
    if anchor is None:
        return None

    pkg = anchor["pkg"]
    text_nodes = [n for n in nodes if n["pkg"] == pkg and (n["text"] or n["desc"])]
    texts: list[str] = []
    for n in text_nodes:
        t = (n["text"] or n["desc"]).strip()
        if t and (not texts or texts[-1] != t):
            texts.append(t)

    buttons = []
    for n in text_nodes:
        t = (n["text"] or n["desc"]).strip()
        if n["clickable"] or "Button" in n["cls"] or norm(t) in KNOWN_LABELS:
            if len(t) <= 40 and t not in [b["label"] for b in buttons]:
                buttons.append({"label": t, "bounds": n["bounds"]})
    button_labels = {b["label"] for b in buttons}

    # Drop the "Google Play Protect" header (short text), not the paragraphs that mention it.
    content = [t for t in texts
               if not ("play protect" in norm(t) and len(t) < 40) and t not in button_labels]
    title = content[0] if content else None
    app_label = None
    rest = content[1:]
    if rest and len(rest[0]) < 60 and not rest[0].rstrip().endswith("."):
        app_label, rest = rest[0], rest[1:]
    body = "\n".join(rest)

    return {
        "dialog_package": pkg,
        "title": title,
        "app_label": app_label,
        "body": body,
        "texts": texts,
        "buttons": buttons,
        "fingerprint": hashlib.sha1("\n".join(texts).encode("utf-8")).hexdigest(),
    }


def choose_action(alert: dict, allow_scan: bool):
    """Return (action_name, button | None). Actions: click:<label>, back, wait."""
    if not alert["buttons"]:
        return "wait", None  # e.g. a "Scanning…" screen
    by_label = {norm(b["label"]): b for b in alert["buttons"]}
    if allow_scan:
        for lab in SCAN_LABELS:
            if lab in by_label:
                return f"click:{by_label[lab]['label']}", by_label[lab]
    for lab in DISMISS_LABELS:
        if lab in by_label:
            return f"click:{by_label[lab]['label']}", by_label[lab]
    return "back", None  # only forbidden or unknown buttons


def _perform(d, action: str, button: dict | None) -> None:
    if action.startswith("click:") and button:
        c = _center(button["bounds"])
        if c:
            call_timeout(d.click, UI_CALL_TIMEOUT, *c)
            return
        call_timeout(d.press, UI_CALL_TIMEOUT, "back")
    elif action == "back":
        call_timeout(d.press, UI_CALL_TIMEOUT, "back")


def watch(d, install, shots_dir: Path, prefix: str, timeout: float, grace: float = 4.0,
          poll: float = 0.7, allow_scan: bool = True, wait_limit: float = 25.0) -> list[dict]:
    """Watch the screen during the install and handle each Play Protect dialog."""
    alerts: list[dict] = []
    attempts: dict[str, int] = {}
    first_seen: dict[str, float] = {}
    stalls = 0  # stuck screen reads in a row (agent / phone unreachable)
    t0 = time.time()

    while time.time() - t0 < timeout:
        if install.done and install.finished_at and time.time() - install.finished_at > grace:
            break
        try:
            alert = find_alert(read_nodes(d))
            stalls = 0
        except TimeoutExpired:
            stalls += 1
            if stalls >= 3:  # ~60s with no response: give up this APK, the run continues
                break
            continue
        except Exception:  # noqa: BLE001  (screen transitions, busy agent…)
            time.sleep(poll)
            continue
        if alert is None:
            time.sleep(poll)
            continue

        fp = alert["fingerprint"]
        action, button = choose_action(alert, allow_scan)

        if fp not in first_seen:
            first_seen[fp] = time.time()
            shot = shots_dir / f"{prefix}_{len(alerts) + 1}.png"
            try:
                call_timeout(d.screenshot, UI_CALL_TIMEOUT, str(shot))
                alert["screenshot"] = str(shot)
            except Exception:  # noqa: BLE001
                alert["screenshot"] = None
            alert["detected_after_s"] = round(time.time() - t0, 2)
            alert["action"] = action
            alerts.append(alert)
        else:
            # Same dialog still shown: missed click or a waiting screen.
            attempts[fp] = attempts.get(fp, 0) + 1
            if action == "wait" and time.time() - first_seen[fp] > wait_limit:
                action, button = "back", None
            elif action != "wait" and attempts[fp] >= 3:
                action, button = "back", None

        if action != "wait":
            _perform(d, action, button)
            time.sleep(1.2)
        else:
            time.sleep(poll)

    return alerts
