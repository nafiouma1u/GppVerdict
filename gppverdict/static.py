"""Static APK metadata (before installation)."""
from __future__ import annotations

import hashlib
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_apk_class():
    try:  # androguard >= 4
        from loguru import logger
        logger.remove()  # androguard 4 is very noisy
    except Exception:  # noqa: BLE001
        pass
    try:
        from androguard.core.apk import APK
    except ImportError:  # androguard 3.x
        from androguard.core.bytecodes.apk import APK
    return APK


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:  # noqa: BLE001
        return default


def analyze(path: Path) -> dict:
    info = {"package": None, "version_name": None, "version_code": None, "app_label": None,
            "min_sdk": None, "target_sdk": None, "permissions": [], "static_error": None}
    try:
        apk = _load_apk_class()(str(path))
    except Exception as e:  # noqa: BLE001
        info["static_error"] = f"{type(e).__name__}: {e}"[:500]
        return info
    info.update({
        "package": _safe(apk.get_package),
        "version_name": _safe(apk.get_androidversion_name),
        "version_code": _safe(apk.get_androidversion_code),
        "app_label": _safe(apk.get_app_name),
        "min_sdk": _safe(apk.get_min_sdk_version),
        "target_sdk": _safe(apk.get_target_sdk_version),
        "permissions": sorted(_safe(apk.get_permissions, []) or []),
    })
    return info
