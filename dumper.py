"""ZovPatron dump engine: Unity IL2CPP / Mono, generic ELF (any engine), PE (exe/dll)."""
from __future__ import annotations

import asyncio
import json
import mmap
import os
import re
import shutil
import zipfile
from pathlib import Path

# ---- config ---------------------------------------------------------------
IL2CPP_DIR = Path(os.getenv("IL2CPP_DIR", "/opt/il2cppdumper"))  # Il2CppDumper.dll lives here
ILSPY = os.getenv("ILSPY_CMD", "ilspycmd")                       # dotnet tool install -g ilspycmd
TIMEOUT = 900                                                    # seconds per external tool
MAX_EXTRACT = 1_500_000_000                                      # bytes, per extracted member
MAX_STR_LINES = 200_000
ARCH_PRIO = ["arm64-v8a", "armeabi-v7a", "x86_64", "x86", "armeabi"]
SKIP_LIBS = {"libc++_shared.so", "libc.so", "libm.so", "libdl.so", "liblog.so"}
ENGINE_HINTS = (
    ("libil2cpp.so", "Unity IL2CPP"), ("libunity.so", "Unity"), ("libue4.so", "Unreal Engine"),
    ("libgodot", "Godot"), ("libcocos", "Cocos2d-x"), ("libgdx", "libGDX"),
    ("libflutter.so", "Flutter"), ("libhermes", "React Native"), ("libmonosgen", "Xamarin / Mono"),
)


class DumpError(Exception):
    pass


class NeedMeta(Exception):
    """IL2CPP binary received alone, global-metadata.dat is required."""


# ---- helpers --------------------------------------------------------------
def safe_name(name: str) -> str:
    return re.sub(r"[^\w.\-]", "_", name)[:120] or "input.bin"


async def _run(cmd: list[str], stdin: bytes = b"", cwd: str | None = None, stdout=None):
    try:
        p = await asyncio.create_subprocess_exec(
            *cmd, cwd=cwd, stdin=asyncio.subprocess.PIPE,
            stdout=stdout or asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except FileNotFoundError:
        raise DumpError(f"на сервере нет {cmd[0]}")
    try:
        out, err = await asyncio.wait_for(p.communicate(stdin), TIMEOUT)
    except asyncio.TimeoutError:
        p.kill()
        await p.wait()
        raise DumpError("таймаут дампа (файл слишком тяжёлый или защищён)")
    return p.returncode, out or b"", err or b""


def _tail(*chunks: bytes, n: int = 500) -> str:
    return b"".join(chunks).decode("utf8", "ignore").strip()[-n:]


def _arch(parts: list[str]) -> str:
    return next((p for p in parts if p in ARCH_PRIO), "?")


def _pick(items: list[tuple[str, Path]]) -> Path | None:
    if not items:
        return None
    items = sorted(items, key=lambda t: ARCH_PRIO.index(t[0]) if t[0] in ARCH_PRIO else 99)
    return items[0][1]


def _strings(path: Path, wide: bool = False) -> list[str]:
    if path.stat().st_size == 0:
        return []
    pat = re.compile(rb"(?:[\x20-\x7e]\x00){6,}" if wide else rb"[\x20-\x7e]{6,}")
    res: list[str] = []
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
        for mt in pat.finditer(m):
            res.append(mt.group()[:800].decode("utf-16le" if wide else "ascii", "ignore"))
            if len(res) >= MAX_STR_LINES:
                break
    return res


def is_il2cpp_binary(path: Path) -> bool:
    if path.stat().st_size == 0:
        return False
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
        return m.find(b"il2cpp_init") != -1


def is_dotnet(path: Path) -> bool:
    import pefile
    pe = pefile.PE(str(path), fast_load=True)
    try:
        dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        return len(dd) > 14 and dd[14].VirtualAddress != 0 and dd[14].Size != 0
    finally:
        pe.close()


# ---- archive scan ---------------------------------------------------------
class Found:
    def __init__(self) -> None:
        self.il2cpp: list[tuple[str, Path]] = []
        self.gasm: list[Path] = []
        self.meta: list[Path] = []
        self.managed: dict[str, Path] = {}
        self.native: list[tuple[str, Path]] = []
        self.names: set[str] = set()
        self.pe: list[Path] = []
        self.idx = 0


def _extract(zf: zipfile.ZipFile, info: zipfile.ZipInfo, dest: Path, f: Found) -> Path:
    if info.file_size > MAX_EXTRACT:
        raise DumpError(f"{Path(info.filename).name}: слишком большой внутри архива")
    f.idx += 1
    p = dest / f"{f.idx}_{safe_name(Path(info.filename).name)}"
    written = 0
    with zf.open(info) as s, open(p, "wb") as d:
        while chunk := s.read(1 << 20):
            written += len(chunk)
            if written > MAX_EXTRACT:
                raise DumpError("архив подозрительно раздувается (zip-bomb?)")
            d.write(chunk)
    return p


def scan(path: Path, dest: Path, f: Found, depth: int = 0, pe: bool = False) -> None:
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        raise DumpError("битый или не-zip архив")
    with zf:
        for i in zf.infolist():
            if i.is_dir():
                continue
            parts = i.filename.replace("\\", "/").split("/")
            low = parts[-1].lower()
            if low.endswith(".so"):
                f.names.add(low)
            if low == "libil2cpp.so":
                f.il2cpp.append((_arch(parts), _extract(zf, i, dest, f)))
            elif low == "global-metadata.dat":
                f.meta.append(_extract(zf, i, dest, f))
            elif low == "gameassembly.dll" and pe:
                f.gasm.append(_extract(zf, i, dest, f))
            elif low in ("assembly-csharp.dll", "assembly-csharp-firstpass.dll"):
                f.managed.setdefault(low, _extract(zf, i, dest, f))
            elif low.endswith(".so") and low not in SKIP_LIBS and i.file_size > 30_000 and len(f.native) < 40:
                f.native.append((_arch(parts), _extract(zf, i, dest, f)))
            elif low.endswith(".apk") and depth < 2:
                scan(_extract(zf, i, dest, f), dest, f, depth + 1, pe)
            elif low.endswith(".exe") and pe and len(f.pe) < 5:
                f.pe.append(_extract(zf, i, dest, f))


# ---- tools ----------------------------------------------------------------
def _prep_il2cpp_config() -> None:
    cfg = IL2CPP_DIR / "config.json"
    try:
        data = json.loads(cfg.read_text()) if cfg.exists() else {}
        data.update({
            "RequireAnyKey": False, "GenerateDummyDll": True, "GenerateStruct": True,
            "DummyDllAddToken": True, "DumpMethod": True, "DumpField": True, "DumpProperty": True,
            "DumpAttribute": True, "DumpFieldOffset": True, "DumpMethodOffset": True,
            "DumpTypeDefIndex": True,
        })
        cfg.write_text(json.dumps(data, indent=2))
    except OSError:
        pass


async def il2cpp_dump(lib: Path, meta: Path, out: Path) -> None:
    if not (IL2CPP_DIR / "Il2CppDumper.dll").exists():
        raise DumpError("il2cppdumper не установлен на сервере")
    _prep_il2cpp_config()
    out.mkdir(parents=True, exist_ok=True)
    # b"0\n" answers the "input il2cpp dump address or 0 to force continue" prompt if it shows up
    rc, o, e = await _run(
        ["dotnet", str(IL2CPP_DIR / "Il2CppDumper.dll"), str(lib), str(meta), str(out) + os.sep],
        stdin=b"0\n" * 3, cwd=str(IL2CPP_DIR))
    if not (out / "dump.cs").exists():
        raise DumpError("il2cppdumper не справился (метадата зашифрована / либа запакована?)\n" + _tail(o, e))


async def mono_dump(asm: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    with open(dst, "wb") as fh:
        rc, _, e = await _run([ILSPY, str(asm)], stdout=fh)
    if rc != 0 or dst.stat().st_size < 50:
        raise DumpError("ilspycmd не смог декомпилировать: " + _tail(e, n=300))


def elf_dump(path: Path, dst: Path) -> None:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    dst.parent.mkdir(parents=True, exist_ok=True)
    L = [f"# {path.name}", ""]
    try:
        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            L.append(f"class: ELF{elf.elfclass}   machine: {elf['e_machine']}   entry: {elf['e_entry']:#x}")
            dyn = elf.get_section_by_name(".dynamic")
            if dyn:
                for t in dyn.iter_tags():
                    if t.entry.d_tag == "DT_SONAME":
                        L.append(f"soname: {t.soname}")
                    elif t.entry.d_tag == "DT_NEEDED":
                        L.append(f"needed: {t.needed}")
            L += ["", "## sections"]
            L += [f"{s.name:<24} addr={s['sh_addr']:#010x} size={s['sh_size']:#x}" for s in elf.iter_sections()]
            defined, imported, seen = [], [], set()
            for s in elf.iter_sections():
                if not isinstance(s, SymbolTableSection):
                    continue
                for sym in s.iter_symbols():
                    if not sym.name:
                        continue
                    if sym["st_shndx"] == "SHN_UNDEF":
                        imported.append(sym.name)
                    elif (sym.name, sym["st_value"]) not in seen:
                        seen.add((sym.name, sym["st_value"]))
                        defined.append(f"{sym['st_value']:#012x} {sym['st_size']:>8} {sym.name}")
            L += ["", f"## defined symbols ({len(defined)})  [addr size name]", *defined]
            L += ["", f"## imports ({len(imported)})", *sorted(set(imported))]
    except Exception as ex:  # not a clean ELF (packed / stripped section headers)
        L.append(f"(elf parse failed: {ex}) — strings only")
    L += ["", "## strings", *_strings(path)]
    dst.write_text("\n".join(L), encoding="utf8", errors="ignore")


def pe_dump(path: Path, outdir: Path) -> None:
    import pefile
    outdir.mkdir(parents=True, exist_ok=True)
    pe = pefile.PE(str(path))
    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    L = [f"# {path.name}", "",
         f"machine: {fh.Machine:#06x}   {'PE32+' if oh.Magic == 0x20b else 'PE32'}   dll: {pe.is_dll()}",
         f"timestamp: {fh.TimeDateStamp}",
         f"imagebase: {oh.ImageBase:#x}   entry_rva: {oh.AddressOfEntryPoint:#x}   subsystem: {oh.Subsystem}",
         "", "## sections"]
    for s in pe.sections:
        ent = s.get_entropy()
        nm = s.Name.rstrip(b"\0").decode(errors="ignore")
        L.append(f"{nm:<10} va={s.VirtualAddress:#010x} vsize={s.Misc_VirtualSize:#x} "
                 f"raw={s.SizeOfRawData:#x} entropy={ent:.2f}{'  <-- packed/encrypted?' if ent > 7.2 else ''}")
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        L += ["", "## imports"]
        for e in pe.DIRECTORY_ENTRY_IMPORT:
            L.append(e.dll.decode(errors="ignore"))
            L += [f"    {i.name.decode(errors='ignore') if i.name else 'ord' + str(i.ordinal)}" for i in e.imports]
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        L += ["", "## exports  [addr name]"]
        for s in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            L.append(f"{oh.ImageBase + s.address:#014x} {s.name.decode(errors='ignore') if s.name else 'ord' + str(s.ordinal)}")
    try:
        for fi in pe.FileInfo:
            for e in fi:
                if hasattr(e, "StringTable"):
                    for st in e.StringTable:
                        L += ["", "## version info"] + [f"{k.decode(errors='ignore')}: {v.decode(errors='ignore')}" for k, v in st.entries.items()]
    except Exception:
        pass
    pe.close()
    (outdir / f"{path.stem}.txt").write_text("\n".join(L), encoding="utf8", errors="ignore")
    strs = ["## ascii", *_strings(path), "", "## utf-16", *_strings(path, wide=True)]
    (outdir / f"{path.stem}_strings.txt").write_text("\n".join(strs), encoding="utf8", errors="ignore")


# ---- main entry -----------------------------------------------------------
def _engine(names: set[str]) -> str:
    for key, label in ENGINE_HINTS:
        if any(n.startswith(key) or key in n for n in names):
            return label
    return "неизвестный / свой движок"


async def _dump_archive(src: Path, work: Path, out: Path, pe: bool) -> str:
    ex = work / "x"
    ex.mkdir(exist_ok=True)
    f = Found()
    await asyncio.to_thread(scan, src, ex, f, 0, pe)
    lib = _pick(f.il2cpp) or (f.gasm[0] if f.gasm else None)
    meta = max(f.meta, key=lambda p: p.stat().st_size) if f.meta else None
    engine = _engine(f.names)
    note = ""

    if lib and meta:
        await il2cpp_dump(lib, meta, out)
        return "Unity IL2CPP · Il2CppDumper"
    if lib and not meta:
        note = " (global-metadata.dat не найден — сделан нативный дамп)"
        f.native.append(("?", lib))

    if f.managed:
        if "assembly-csharp.dll" in f.managed:
            await mono_dump(f.managed["assembly-csharp.dll"], out / "dump.cs")
        if "assembly-csharp-firstpass.dll" in f.managed:
            await mono_dump(f.managed["assembly-csharp-firstpass.dll"], out / "dump_firstpass.cs")
        (out / "Managed").mkdir(exist_ok=True)
        for p in f.managed.values():
            shutil.copy(p, out / "Managed" / p.name.split("_", 1)[-1])
        return "Unity Mono · ILSpy"

    if f.native:
        best = min((a for a, _ in f.native), key=lambda a: ARCH_PRIO.index(a) if a in ARCH_PRIO else 99)
        libs = sorted((p for a, p in f.native if a == best), key=lambda p: p.stat().st_size, reverse=True)[:12]
        for p in libs:
            await asyncio.to_thread(elf_dump, p, out / "native" / (p.name.split("_", 1)[-1] + ".txt"))
        return f"{engine} · ELF symbols+strings ({best}, {len(libs)} lib){note}"

    if pe and f.pe:
        for p in f.pe:
            await _dump_pe_file(p, out)
        return f"PE · {len(f.pe)} exe"
    raise DumpError("не нашёл ни il2cpp, ни Mono-сборок, ни нативных библиотек")


async def _dump_pe_file(src: Path, out: Path) -> str:
    if await asyncio.to_thread(is_dotnet, src):
        await mono_dump(src, out / "dump.cs")
        return ".NET · ILSpy"
    await asyncio.to_thread(pe_dump, src, out)
    return "Native PE · headers / imports / exports / strings"


async def dump(src: Path, work: Path, mode: str, meta: Path | None = None) -> tuple[Path, str]:
    """mode: 'apk' | 'exe'. Returns (output dir, short report). Raises DumpError / NeedMeta."""
    out = work / "out"
    out.mkdir(exist_ok=True)

    if meta is not None:
        await il2cpp_dump(src, meta, out)
        return out, "Unity IL2CPP · Il2CppDumper"

    with open(src, "rb") as fh:
        head = fh.read(4)

    if head[:2] == b"PK":
        rep = await _dump_archive(src, work, out, pe=(mode == "exe"))
    elif head == b"\x7fELF":
        if await asyncio.to_thread(is_il2cpp_binary, src):
            raise NeedMeta
        await asyncio.to_thread(elf_dump, src, out / "native" / (src.name + ".txt"))
        rep = "ELF · symbols+strings"
    elif head[:2] == b"MZ":
        if mode != "exe":
            raise DumpError("exe/dll дампятся только в режиме EXE (нужна подписка)")
        if src.name.lower() == "gameassembly.dll":
            raise NeedMeta
        rep = await _dump_pe_file(src, out)
    else:
        raise DumpError("формат не поддерживается (нужен apk / xapk / zip / so" + (" / exe / dll)" if mode == "exe" else ")"))

    (out / "report.txt").write_text(f"ZovPatron dump\nsource: {src.name}\nresult: {rep}\n", encoding="utf8")
    return out, rep


def make_zip(out: Path, dst: Path, limit: int) -> tuple[int, bool]:
    """Zip the dump. If it exceeds Telegram's limit, retry without DummyDll/*.dll. Returns (size, light)."""
    def build(light: bool) -> int:
        with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            for p in sorted(out.rglob("*")):
                if p.is_file():
                    if light and ("DummyDll" in p.parts or p.suffix.lower() == ".dll"):
                        continue
                    z.write(p, p.relative_to(out))
        return dst.stat().st_size

    size = build(False)
    if size <= limit:
        return size, False
    size = build(True)
    if size > limit:
        raise DumpError("архив с дампом больше лимита Telegram")
    return size, True
