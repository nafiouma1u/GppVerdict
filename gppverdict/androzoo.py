"""AndroZoo download client (https://androzoo.uni.lu/api_doc).

Downloads an APK by its sha256, verifies the digest, and caches it on disk so a
resumed run does not re-download it."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Callable

import requests

API_URL = "https://androzoo.uni.lu/api/download"


class AndroZooError(RuntimeError):
    pass


def read_api_key(explicit: str | None, key_file: Path | None) -> str:
    if explicit:
        return explicit.strip()
    if key_file and key_file.exists():
        return key_file.read_text(encoding="utf-8").strip()
    raise AndroZooError("Missing AndroZoo API key: pass --apikey or create the .androzoo_key file.")


class AndroZoo:
    def __init__(self, apikey: str, cache_dir: Path, timeout: int = 180):
        if not apikey or any(c in apikey for c in "${}"):
            raise AndroZooError("Invalid API key.")
        self.apikey = apikey
        self.cache_dir = cache_dir
        self.timeout = timeout
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()

    def cached_path(self, sha256: str) -> Path:
        return self.cache_dir / f"{sha256.lower()}.apk"

    def download(self, sha256: str, on_chunk: Callable[[int, int | None], None] | None = None,
                 verify: bool = True) -> Path:
        """Download the APK with hash `sha256`. Returns the local path.

        on_chunk(received, total) is called for each block for progress reporting
        (total may be None if the server does not send Content-Length).
        """
        sha = sha256.lower()
        dest = self.cached_path(sha)
        if dest.exists() and verify and _sha256(dest) == sha:
            if on_chunk:
                size = dest.stat().st_size
                on_chunk(size, size)
            return dest

        tmp = dest.with_suffix(".apk.part")
        try:
            with self.session.get(API_URL, params={"apikey": self.apikey, "sha256": sha},
                                  stream=True, timeout=self.timeout) as r:
                if r.status_code == 404:
                    raise AndroZooError(f"APK {sha[:16]} not found on AndroZoo (404).")
                if r.status_code in (401, 403):
                    raise AndroZooError(f"Access denied by AndroZoo ({r.status_code}): check the API key.")
                if r.status_code != 200:
                    raise AndroZooError(f"AndroZoo returned {r.status_code} for {sha[:16]}.")
                total = int(r.headers.get("content-length") or 0) or None
                h = hashlib.sha256()
                got = 0
                with open(tmp, "wb") as f:
                    for chunk in r.iter_content(1 << 16):
                        if not chunk:
                            continue
                        f.write(chunk)
                        h.update(chunk)
                        got += len(chunk)
                        if on_chunk:
                            on_chunk(got, total)
            if verify and h.hexdigest() != sha:
                raise AndroZooError(f"Digest mismatch: expected {sha[:16]}, got {h.hexdigest()[:16]}.")
            tmp.replace(dest)
            return dest
        except requests.RequestException as e:
            # A requests exception can embed the full URL, including ?apikey=…; redact it.
            msg = str(e).replace(self.apikey, "***")
            raise AndroZooError(f"Network error for {sha[:16]}: {msg}") from e
        finally:
            tmp.unlink(missing_ok=True)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
