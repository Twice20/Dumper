"""Pure-python carver: embedded PE / ZIP / 7z / PNG / base64-encoded PE inside any binary. No deps."""
from __future__ import annotations

import base64
import hashlib
import io
import mmap
import re
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path

MACHINES = {0x14C, 0x8664, 0x1C0, 0x1C4, 0xAA64}
B64_PE = re.compile(rb"TV[oqpAQrR][A-Za-z0-9+/]")      # base64 of "MZ" + next byte
B64_RUN = re.compile(rb"[A-Za-z0-9+/=\r\n]+")
MAX_FILES = 40
MAX_TOTAL = 1_000_000_000
MAX_PNG = 20


@dataclass
class Hit:
    start: int
    end: int
    kind: str          # pe | zip | 7z | png
    origin: str
    data: bytes | None = None


# ---- PE helpers -----------------------------------------------------------
def pe_size(m, off: int, limit: int) -> int | None:
    """File-layout size of the PE image at `off`, or None if it is not a sane PE."""
    if off + 0x40 > limit or m[off:off + 2] != b"MZ":
        return None
    lfa = struct.unpack_from("<I", m, off + 0x3C)[0]
    if lfa < 0x40 or lfa > 0x1000 or off + lfa + 24 > limit:
        return None
    p = off + lfa
    if m[p:p + 4] != b"PE\0\0":
        return None
    machine, nsec, _, _, _, sopt, _ = struct.unpack_from("<HHIIIHH", m, p + 4)
    if machine not in MACHINES or not 1 <= nsec <= 96 or sopt < 0x60:
        return None
    opt = p + 24
    magic = struct.unpack_from("<H", m, opt)[0]
    if magic not in (0x10B, 0x20B):
        return None
    sizeof_headers = struct.unpack_from("<I", m, opt + 60)[0]
    sec = opt + sopt
    if sec + nsec * 40 > limit:
        return None
    end = sizeof_headers
    for i in range(nsec):
        raw_size, raw_ptr = struct.unpack_from("<II", m, sec + i * 40 + 16)
        if raw_size:
            end = max(end, raw_ptr + raw_size)
    dd = opt + (96 if magic == 0x10B else 112)          # data directories
    if dd + 40 <= limit:
        cert_off, cert_size = struct.unpack_from("<II", m, dd + 32)   # security directory (file offset)
        if cert_off and cert_size and cert_off + cert_size <= limit - off:
            end = max(end, cert_off + cert_size)
    if end < 0x200 or off + end > limit:
        return None
    return end


def pe_kind(data: bytes) -> str | None:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    lfa = struct.unpack_from("<I", data, 0x3C)[0]
    if lfa + 24 > len(data) or data[lfa:lfa + 4] != b"PE\0\0":
        return None
    chars = struct.unpack_from("<H", data, lfa + 22)[0]
    return "dll" if chars & 0x2000 else "exe"


def sniff(data: bytes) -> str:
    """File extension guess from content."""
    if data[:2] == b"MZ":
        k = pe_kind(data)
        if k:
            return "." + k
    sigs = ((b"\x7fELF", ".elf"), (b"PK\x03\x04", ".zip"), (b"7z\xbc\xaf\x27\x1c", ".7z"),
            (b"\x89PNG\r\n\x1a\n", ".png"), (b"Rar!\x1a\x07", ".rar"), (b"\x1f\x8b\x08", ".gz"),
            (b"OTTO", ".otf"), (b"\x00\x01\x00\x00\x00", ".ttf"), (b"\xff\xd8\xff", ".jpg"),
            (b"\x00\x00\x01\x00", ".ico"), (b"BM", ".bmp"), (b"RIFF", ".riff"), (b"SQLite format 3", ".db"),
            (b"dex\n", ".dex"), (b"\xca\xfe\xba\xbe", ".class"))
    for sig, ext in sigs:
        if data.startswith(sig):
            return ext
    head = data[:4096]
    if head[:2] in (b"\xff\xfe", b"\xfe\xff") or head.lstrip()[:5] == b"<?xml":
        return ".xml" if b"<?xml" in head[:64].replace(b"\x00", b"") else ".txt"
    if head and sum(c in b"\t\r\n" or 32 <= c < 127 for c in head) / len(head) > 0.95:
        return ".json" if head.lstrip()[:1] in (b"{", b"[") else ".txt"
    return ".bin"


# ---- finders --------------------------------------------------------------
def find_pe(m, n: int) -> list[Hit]:
    hits, pos = [], 0
    while (p := m.find(b"PE\0\0", pos)) != -1:
        pos = p + 4
        lo = max(0, p - 0x1000)
        s = m.rfind(b"MZ", lo, p)
        while s != -1 and s >= lo:
            if s + 0x40 <= n and struct.unpack_from("<I", m, s + 0x3C)[0] == p - s:
                break
            s = m.rfind(b"MZ", lo, s) if s > lo else -1
        if s == -1:
            continue
        size = pe_size(m, s, n)
        if size:
            hits.append(Hit(s, s + size, "pe", f"carved@{s:#x}"))
    return hits


def find_zip(m, n: int) -> list[Hit]:
    hits, pos = [], 0
    while (s := m.find(b"PK\x03\x04", pos)) != -1:
        e = m.find(b"PK\x05\x06", s)
        if e == -1 or e + 22 > n:
            break
        end = min(n, e + 22 + struct.unpack_from("<H", m, e + 20)[0])
        try:
            with zipfile.ZipFile(io.BytesIO(bytes(m[s:end]))) as z:
                ok = bool(z.namelist())
        except Exception:
            ok = False
        if ok:
            hits.append(Hit(s, end, "zip", f"carved@{s:#x}"))
            pos = end
        else:
            pos = s + 4
    return hits


def find_7z(m, n: int) -> list[Hit]:
    hits, pos = [], 0
    while (s := m.find(b"7z\xbc\xaf\x27\x1c", pos)) != -1:
        pos = s + 6
        if s + 32 > n:
            break
        off, size = struct.unpack_from("<QQ", m, s + 12)
        end = s + 32 + off + size
        if size and end <= n:
            hits.append(Hit(s, end, "7z", f"carved@{s:#x}"))
            pos = end
    return hits


def find_png(m, n: int) -> list[Hit]:
    hits, pos = [], 0
    while (s := m.find(b"\x89PNG\r\n\x1a\n", pos)) != -1:
        e = m.find(b"IEND\xaeB`\x82", s)
        if e == -1:
            break
        hits.append(Hit(s, e + 8, "png", f"carved@{s:#x}"))
        pos = e + 8
    return hits


def find_b64_pe(m, n: int) -> list[Hit]:
    """PE files hidden as base64 text (common in loaders). Candidates are validated by decoding."""
    hits, skip_until = [], 0
    for mt in B64_PE.finditer(m):
        s = mt.start()
        if s < skip_until:
            continue
        run = B64_RUN.match(m, s)
        if not run or run.end() - s < 700:
            continue
        skip_until = run.end()
        raw = run.group().translate(None, b"\r\n")
        raw = raw[: len(raw) // 4 * 4]
        try:
            data = base64.b64decode(raw)
        except Exception:
            continue
        size = pe_size(data, 0, len(data))
        if size:
            hits.append(Hit(s, run.end(), "pe", f"base64@{s:#x}", data[:size]))
    return hits


# ---- main -----------------------------------------------------------------
def carve(path: Path, outdir: Path, seen: set[str]) -> list[dict]:
    """Carve embedded files out of `path` into `outdir`. Returns records for index.txt."""
    n = path.stat().st_size
    if n < 0x200:
        return []
    recs: list[dict] = []
    total, pngs = 0, 0
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
        hits = find_pe(m, n) + find_zip(m, n) + find_7z(m, n) + find_png(m, n) + find_b64_pe(m, n)
        hits = [h for h in hits if h.start != 0]                 # offset 0 is the file itself
        hits.sort(key=lambda h: (h.start, -(h.end - h.start)))
        last_end = 0
        for h in hits:
            if h.start < last_end:
                continue
            if len(recs) >= MAX_FILES or total > MAX_TOTAL:
                break
            if h.kind == "png":
                if pngs >= MAX_PNG or h.end - h.start < 1024:
                    continue
                pngs += 1
            data = h.data if h.data is not None else bytes(m[h.start:h.end])
            last_end = h.end
            sha = hashlib.sha256(data).hexdigest()
            if sha in seen:
                continue
            seen.add(sha)
            ext = sniff(data) if h.kind == "pe" else "." + h.kind
            outdir.mkdir(parents=True, exist_ok=True)
            name = f"{h.origin.replace('@', '_')}{ext}"
            (outdir / name).write_bytes(data)
            total += len(data)
            recs.append({"name": name, "origin": h.origin, "size": len(data), "sha256": sha})
    return recs
