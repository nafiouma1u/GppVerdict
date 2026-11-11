"""Read the AndroZoo catalog (gone_apps.tsv, optionally inside a .tar.gz) and draw a
sample stratified by VirusTotal detection count."""
from __future__ import annotations

import io
import random
import tarfile
from pathlib import Path
from typing import Callable, Iterator

# (name, vt_detection min, max inclusive; None = no upper bound)
BUCKETS = [("vt0", 0, 0), ("vt1-4", 1, 4), ("vt5-14", 5, 14), ("vt15+", 15, None)]


def bucket_of(vt: int) -> str:
    for name, lo, hi in BUCKETS:
        if vt >= lo and (hi is None or vt <= hi):
            return name
    return "vt0"


class _CountingReader(io.RawIOBase):
    """Count the bytes read from the (compressed) file, for the progress bar."""

    def __init__(self, fh, on_read: Callable[[int], None] | None):
        self.fh, self.on_read = fh, on_read

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        n = self.fh.readinto(b)
        if n and self.on_read:
            self.on_read(n)
        return n


class _ReadAdapter(io.RawIOBase):
    """Wrap an object that only exposes .read() (e.g. a non-seekable tar stream)."""

    def __init__(self, fh):
        self.fh = fh

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        data = self.fh.read(len(b))
        if not data:
            return 0
        b[:len(data)] = data
        return len(data)


def iter_rows(path: Path, on_read: Callable[[int], None] | None = None) -> Iterator[dict]:
    """Iterate over the TSV/CSV rows as dicts (header columns).

    The file may be raw (.tsv/.csv) or inside a .tar.gz archive. Reading is
    streamed: the whole file is never loaded into memory.
    """
    raw = open(path, "rb")
    try:
        counted = io.BufferedReader(_CountingReader(raw, on_read), 1 << 20)
        if path.name.endswith((".tar.gz", ".tgz")):
            tar = tarfile.open(fileobj=counted, mode="r|gz")
            # Skip macOS AppleDouble files (._xxx, __MACOSX/).
            member = next((m for m in tar if m.isfile()
                           and m.name.endswith((".tsv", ".csv"))
                           and not Path(m.name).name.startswith("._")
                           and "__MACOSX" not in m.name), None)
            if member is None:
                raise ValueError(f"No .tsv/.csv inside {path}")
            stream = io.BufferedReader(_ReadAdapter(tar.extractfile(member)), 1 << 20)
        elif path.name.endswith(".gz"):
            import gzip
            stream = gzip.open(counted, "rb")
        else:
            stream = counted
        text = io.TextIOWrapper(stream, encoding="utf-8", errors="replace")

        sep = None
        header = None
        for line in text:
            line = line.rstrip("\r\n")
            if header is None:
                sep = "\t" if "\t" in line else ","
                header = line.split(sep)
                continue
            parts = line.split(sep)
            if len(parts) == len(header):
                yield dict(zip(header, parts))
    finally:
        raw.close()


def _int(v, default=None):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def _year(row: dict) -> int | None:
    val = row.get("added") or row.get("first_added") or row.get("vt_scan_date") or ""
    return _int(val[:4])


def _enrich(row: dict, wanted: set, max_size, year_min, year_max) -> dict | None:
    """Apply the common filters; return the enriched row, or None if rejected."""
    sha = row.get("sha256")
    if not sha or len(sha) != 64:
        return None
    vt = _int(row.get("vt_detection"))
    if vt is None:
        return None
    b = bucket_of(vt)
    if b not in wanted:
        return None
    size = _int(row.get("apk_size"))
    if max_size and size and size > max_size:
        return None
    yr = _year(row)
    if year_min and (yr is None or yr < year_min):
        return None
    if year_max and (yr is None or yr > year_max):
        return None
    row["vt_detection_int"], row["apk_size_int"], row["year"], row["bucket"] = vt, size, yr, b
    return row


def stream(path: Path, buckets: list[str] | None = None, max_size_mb: float | None = None,
           year_min: int | None = None, year_max: int | None = None,
           on_read: Callable[[int], None] | None = None) -> Iterator[dict]:
    """Walk the WHOLE catalog in file order (for `--all`), applying the same filters
    as `sample`. Streamed read: constant memory."""
    wanted = set(buckets or [b[0] for b in BUCKETS])
    max_size = max_size_mb * 1e6 if max_size_mb else None
    for row in iter_rows(path, on_read):
        enriched = _enrich(row, wanted, max_size, year_min, year_max)
        if enriched is not None:
            yield enriched


def count(path: Path, buckets: list[str] | None = None, max_size_mb: float | None = None,
          year_min: int | None = None, year_max: int | None = None,
          on_read: Callable[[int], None] | None = None) -> int:
    """Count the rows kept by the filters (one pass over the file)."""
    n = 0
    for _ in stream(path, buckets, max_size_mb, year_min, year_max, on_read):
        n += 1
    return n


def sample(path: Path, per_bucket: int, buckets: list[str] | None = None,
           max_size_mb: float | None = None, year_min: int | None = None,
           year_max: int | None = None, seed: int = 1,
           on_read: Callable[[int], None] | None = None) -> tuple[list[dict], dict]:
    """Reservoir sampling: up to `per_bucket` APKs drawn at random from each
    VirusTotal detection bucket, in a single pass over the file.

    Returns (list of kept rows, per-bucket stats). Each row is enriched with
    `vt_detection_int`, `apk_size_int`, `year` and `bucket`.
    """
    wanted = set(buckets or [b[0] for b in BUCKETS])
    max_size = max_size_mb * 1e6 if max_size_mb else None
    rng = random.Random(seed)
    reservoir: dict[str, list] = {b: [] for b in wanted}
    seen: dict[str, int] = {b: 0 for b in wanted}

    for row in iter_rows(path, on_read):
        row = _enrich(row, wanted, max_size, year_min, year_max)
        if row is None:
            continue
        b = row["bucket"]
        seen[b] += 1
        res = reservoir[b]
        if len(res) < per_bucket:
            res.append(row)
        else:  # random replacement (algorithm R)
            j = rng.randint(0, seen[b] - 1)
            if j < per_bucket:
                res[j] = row

    selected = [r for b in BUCKETS if b[0] in reservoir for r in reservoir[b[0]]]
    rng.shuffle(selected)
    stats = {b: {"seen": seen[b], "selected": len(reservoir[b])} for b in wanted}
    return selected, stats
