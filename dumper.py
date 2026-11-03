"""ZovPatron dump engine: Unity IL2CPP / Mono, native ELF (any engine), PE (exe/dll) + embedded file extraction."""
from __future__ import annotations

import asyncio
import hashlib
import json
import mmap
import os
import re
import shutil
import struct
import subprocess
import zipfile
import zlib
from pathlib import Path

import carve

# ---- config ---------------------------------------------------------------
IL2CPP_DIR = Path(os.getenv("IL2CPP_DIR", "/opt/il2cppdumper"))  # Il2CppDumper.dll lives here
ILSPY = os.getenv("ILSPY_CMD", "ilspycmd")                       # dotnet tool install -g ilspycmd
TIMEOUT = 900                                                    # seconds per external tool
MAX_EXTRACT = 1_500_000_000                                      # bytes, per extracted archive member
MAX_STR_LINES = 200_000
MAX_FUNCS = 400_000
ARCH_PRIO = ["arm64-v8a", "armeabi-v7a", "x86_64", "x86", "armeabi"]
SKIP_LIBS = {"libc++_shared.so", "libc.so", "libm.so", "libdl.so", "liblog.so"}
ENGINE_HINTS = (
    ("libil2cpp.so", "Unity IL2CPP"), ("libunity.so", "Unity"), ("libue4.so", "Unreal Engine"),
    ("libgodot", "Godot"), ("libcocos", "Cocos2d-x"), ("libgdx", "libGDX"),
    ("libflutter.so", "Flutter"), ("libhermes", "React Native"), ("libmonosgen", "Xamarin / Mono"),
)
PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    ".themida": "Themida", ".winlice": "WinLicense", ".enigma1": "Enigma", ".enigma2": "Enigma",
    ".aspack": "ASPack", ".adata": "ASPack", ".mpress1": "MPRESS", ".mpress2": "MPRESS", ".nsp0": "NsPack",
}
SKIP_RES = {
    "RT_CURSOR", "RT_ICON", "RT_GROUP_CURSOR", "RT_GROUP_ICON", "RT_VERSION", "RT_DIALOG", "RT_MENU",
    "RT_ACCELERATOR", "RT_STRING", "RT_VXD", "RT_DLGINCLUDE", "RT_ANICURSOR", "RT_ANIICON", "RT_TOOLBAR",
    "RT_MESSAGETABLE", "RT_PLUGPLAY", "RT_FONTDIR",
}

# statically linked libraries / frameworks are detected by their signature strings
_SIGS = [
    ("Dear ImGui", rb"ImGui::[A-Za-z]+|imgui\.ini|Dear ImGui|ImGui_Impl\w+"),
    ("MinHook", rb"MH_Initialize|MH_CreateHook|MinHook"),
    ("Detours", rb"DetourAttach|DetourTransactionBegin"),
    ("DirectX 9", rb"Direct3DCreate9"), ("DirectX 11", rb"D3D11CreateDevice\w*"),
    ("DirectX 12", rb"D3D12CreateDevice"), ("DXGI", rb"CreateDXGIFactory\d?"),
    ("Vulkan", rb"vkCreateInstance"), ("OpenGL", rb"wglCreateContext|glClearColor"),
    ("OpenSSL", rb"OpenSSL \d[\w.\- ]{2,24}"), ("zlib", rb"(?:de|in)flate \d\.\d+\.\d+"),
    ("libcurl", rb"libcurl/[\d.]+"), ("SQLite", rb"SQLite format 3|sqlite3_open\w*"),
    ("Lua", rb"Lua 5\.\d|luaL_newstate"), ("nlohmann::json", rb"nlohmann"), ("spdlog", rb"spdlog"),
    ("Boost", rb"boost::|BOOST_"), ("Qt", rb"Qt[56]Core|QtCore"),
    ("Unity", rb"UnityPlayer|\d{4}\.\d+\.\d+[fpb]\d+"),
    ("Unreal Engine", rb"\+\+UE[45]\+Release-[\d.]+|UE4Game|UnrealEngine"),
    ("Godot", rb"Godot Engine v[\d.]+"), ("Cocos2d-x", rb"cocos2d-x[\w .\-]{0,20}"),
    ("FMOD", rb"FMOD_System_Create|FMOD Studio"), ("Wwise", rb"AK::SoundEngine"),
    ("Steamworks", rb"SteamAPI_Init"), ("Discord RPC", rb"Discord_Initialize"),
    ("Python", rb"Py_Initialize|python3\d+\.dll"), ("Go runtime", rb"Go build ID|runtime\.goexit"),
    ("Rust", rb"rustc/[0-9a-f]{8,}|core::panicking"), ("MinGW", rb"__mingw_|mingw-w64"),
    ("Electron/CEF", rb"libcef|Chromium Embedded"),
    ("UPX", rb"UPX!"), ("VMProtect", rb"\.vmp[0-2]"), ("Themida/WinLicense", rb"Themida|WinLicense"),
    ("Enigma Protector", rb"\.enigma[12]"),
]
LIB_SIGS = [(n, re.compile(p)) for n, p in _SIGS]

URL_RE = re.compile(r"https?://[^\s\"'<>\\]{4,}")
IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?")
PATH_RE = re.compile(r"^(?:/[\w.\-$@+]+){2,}/?$|^[A-Za-z]:\\[\w .\\\-$]+$")
JAVA_RE = re.compile(r"^L[\w/$]+;$|^\([\w/;$\[]*\)[\w/;$\[]+$|^[a-z]+(?:\.[\w$]+){2,}$")


class DumpError(Exception):
    pass


class NeedMeta(Exception):
    """IL2CPP binary received alone — global-metadata.dat is required. .lib = what we already have."""
    def __init__(self, lib: Path | None = None) -> None:
        super().__init__()
        self.lib = lib


class NeedLib(Exception):
    """global-metadata.dat received alone — libil2cpp.so / GameAssembly.dll is required. .meta = what we have."""
    def __init__(self, meta: Path) -> None:
        super().__init__()
        self.meta = meta


# ---- helpers --------------------------------------------------------------
def safe_name(name: str) -> str:
    return re.sub(r"[^\w.\-]", "_", name)[:120] or "input.bin"


def _nm(x) -> str:
    return x.decode(errors="ignore") if isinstance(x, bytes) else str(x)


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
    return sorted(items, key=lambda t: ARCH_PRIO.index(t[0]) if t[0] in ARCH_PRIO else 99)[0][1]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


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


def _jni_sigs(path: Path) -> list[str]:
    """Short JNI signatures like (II)V are below the normal string length limit — scan for them separately."""
    if path.stat().st_size == 0:
        return []
    pat = re.compile(rb"(?<=\x00)\([\[\w/;$]{0,80}\)[\[\w/;$]{1,80}(?=\x00)")
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
        return [x.group().decode("ascii", "ignore") for x in pat.finditer(m)][:5000]


def write_strings(items: list[str], dst: Path) -> None:
    uniq = list(dict.fromkeys(items))
    urls, ips, paths, java = [], [], [], []
    for s in uniq:
        if URL_RE.search(s):
            urls.append(s)
        elif PATH_RE.match(s):
            paths.append(s)
        elif JAVA_RE.match(s):
            java.append(s)
        elif IP_RE.fullmatch(s):
            ips.append(s)
    out = []
    for title, lst in (("urls", urls), ("ips", ips), ("paths", paths), ("java / jni", java), ("all", uniq)):
        out += [f"## {title} ({len(lst)})", *lst, ""]
    dst.write_text("\n".join(out), encoding="utf8", errors="ignore")


def detect_libs(path: Path) -> list[str]:
    if path.stat().st_size == 0:
        return []
    res = []
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
        for name, pat in LIB_SIGS:
            mt = pat.search(m)
            if mt:
                res.append(f"{name}  <- {mt.group()[:48].decode('latin1')!r}")
    return res


def demangle(names: list[str]) -> dict[str, str]:
    mangled = sorted({n for n in names if n.startswith("_Z")})
    if not mangled:
        return {}
    try:
        p = subprocess.run(["c++filt"], input="\n".join(mangled), capture_output=True, text=True, timeout=120)
        return dict(zip(mangled, p.stdout.split("\n")))
    except Exception:
        return {}


def is_il2cpp_binary(path: Path) -> bool:
    if path.stat().st_size == 0:
        return False
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
        return m.find(b"il2cpp_init") != -1


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
        self.apks: list[Path] = []
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
            if len(parts) == 1 and low == "androidmanifest.xml":
                f.apks.append(path)
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


def apk_info(path: Path) -> list[str]:
    try:
        from pyaxmlparser import APK
        a = APK(str(path))
        return [f"package: {a.package}", f"app: {a.get_app_name()}",
                f"version: {a.version_name} ({a.version_code})",
                f"min/target sdk: {a.get_min_sdk_version()} / {a.get_target_sdk_version()}",
                f"main activity: {a.get_main_activity()}", "permissions:",
                *[f"  {p}" for p in a.get_permissions()]]
    except Exception:
        return []


# ---- il2cpp / mono --------------------------------------------------------
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


async def ilspy_project(asm: Path, outdir: Path) -> None:
    """Project export: also writes the assembly's embedded resources as files."""
    outdir.mkdir(parents=True, exist_ok=True)
    rc, _, e = await _run([ILSPY, "-p", "-o", str(outdir), str(asm)])
    if rc != 0:
        raise DumpError("ilspy project: " + _tail(e, n=200))


def costura_unpack(proj: Path, dest: Path) -> list[dict]:
    """Costura.Fody keeps dependencies as deflate-compressed managed resources — unpack them."""
    recs = []
    for p in proj.rglob("*"):
        if not p.is_file() or not p.name.lower().startswith("costura"):
            continue
        data = p.read_bytes()
        raw = None
        if p.name.lower().endswith(".compressed"):
            for wb in (-15, 31, 15):
                try:
                    raw = zlib.decompress(data, wb)
                    break
                except zlib.error:
                    continue
        elif data[:2] == b"MZ":
            raw = data
        if raw and raw[:2] == b"MZ":
            dest.mkdir(parents=True, exist_ok=True)
            name = re.sub(r"\.compressed$", "", p.name, flags=re.I)
            (dest / name).write_bytes(raw)
            recs.append({"name": name, "origin": "costura resource", "size": len(raw),
                         "sha256": hashlib.sha256(raw).hexdigest()})
    return recs


# ---- native ELF -----------------------------------------------------------
def elf_dump(path: Path, outdir: Path) -> str:
    """info.txt / symbols.txt / functions.txt / imports.txt / strings.txt for one ELF. Works on stripped libs."""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from elftools.dwarf.callframe import FDE
    outdir.mkdir(parents=True, exist_ok=True)
    info = [f"# {path.name}", f"size: {path.stat().st_size}", f"sha256: {_sha256(path)}"]
    defined: list[tuple[int, int, str, str]] = []
    imported: set[str] = set()
    funcs: list[tuple[int, int]] = []
    try:
        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            info.append(f"class: ELF{elf.elfclass}  machine: {elf['e_machine']}  type: {elf['e_type']}  entry: {elf['e_entry']:#x}")
            dyn = elf.get_section_by_name(".dynamic")
            if dyn:
                for t in dyn.iter_tags():
                    if t.entry.d_tag == "DT_SONAME":
                        info.append(f"soname: {t.soname}")
                    elif t.entry.d_tag == "DT_NEEDED":
                        info.append(f"needed: {t.needed}")
            for sec in elf.iter_sections():
                if sec.name == ".note.gnu.build-id" and hasattr(sec, "iter_notes"):
                    for nt in sec.iter_notes():
                        info.append(f"build-id: {nt['n_desc']}")
            info += ["", "## segments"]
            info += [f"{str(s['p_type']):<16} vaddr={s['p_vaddr']:#010x} memsz={s['p_memsz']:#x} flags={s['p_flags']}"
                     for s in elf.iter_segments()]
            info += ["", "## sections"]
            info += [f"{s.name:<24} addr={s['sh_addr']:#010x} size={s['sh_size']:#x}" for s in elf.iter_sections()]
            seen = set()
            for s in elf.iter_sections():
                if not isinstance(s, SymbolTableSection):
                    continue
                for sym in s.iter_symbols():
                    if not sym.name:
                        continue
                    if sym["st_shndx"] == "SHN_UNDEF":
                        imported.add(sym.name)
                    elif (sym.name, sym["st_value"]) not in seen:
                        seen.add((sym.name, sym["st_value"]))
                        defined.append((sym["st_value"], sym["st_size"], str(sym["st_info"]["type"]).replace("STT_", ""), sym.name))
            try:  # function boundaries from .eh_frame: works even when symbols are stripped
                if elf.has_dwarf_info():
                    di = elf.get_dwarf_info()
                    if di.has_EH_CFI():
                        for e in di.EH_CFI_entries():
                            if isinstance(e, FDE):
                                funcs.append((e.header["initial_location"], e.header["address_range"]))
                                if len(funcs) >= MAX_FUNCS:
                                    break
            except Exception as ex:
                info.append(f"(eh_frame parse failed: {ex})")
    except Exception as ex:  # packed / stripped section headers
        info.append(f"(elf parse failed: {ex}) — only strings")

    dem = demangle([d[3] for d in defined] + list(imported))
    nice = lambda n: dem.get(n, n)  # noqa: E731
    defined.sort()
    names_at = {a & ~1: nice(n) for a, _, t, n in defined if t in ("FUNC", "GNU_IFUNC") and a}
    jni = [nice(n) for _, _, _, n in defined if n.startswith("Java_") or n == "JNI_OnLoad"]
    sym_lines = [f"{a:#012x} {s:>8} {t:<7} {nice(n)}" for a, s, t, n in defined]
    (outdir / "symbols.txt").write_text(
        "\n".join([f"## jni ({len(jni)})", *jni, "", f"## defined symbols ({len(defined)})  [addr size type name]", *sym_lines]),
        encoding="utf8", errors="ignore")
    (outdir / "imports.txt").write_text("\n".join(sorted(nice(n) for n in imported)), encoding="utf8", errors="ignore")
    funcs = sorted(set(funcs))
    (outdir / "functions.txt").write_text(
        "\n".join(f"{a:#012x} {s:>8} {names_at.get(a & ~1, f'sub_{a:x}')}" for a, s in funcs), encoding="utf8")
    libs = detect_libs(path)
    info += ["", "## detected libraries / engines", *(libs or ["(nothing recognised)"])]
    (outdir / "info.txt").write_text("\n".join(info), encoding="utf8", errors="ignore")
    write_strings(_strings(path) + _jni_sigs(path), outdir / "strings.txt")
    return f"{path.name}: {len(defined)} sym, {len(funcs)} func" + (f", libs: {', '.join(l.split('  <-')[0] for l in libs[:5])}" if libs else "")


# ---- native PE ------------------------------------------------------------
def _pe_resources(pe, outdir: Path, seen: set[str]) -> list[dict]:
    import pefile
    recs: list[dict] = []
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if not root:
        return recs
    for t in root.entries:
        tname = _nm(t.name) if t.name else pefile.RESOURCE_TYPE.get(getattr(t, "id", None), f"TYPE{getattr(t, 'id', 0)}")
        if tname in SKIP_RES:
            continue
        for n in getattr(t.directory, "entries", []):
            nname = _nm(n.name) if n.name else str(getattr(n, "id", 0))
            for lg in getattr(n.directory, "entries", []):
                if len(recs) >= 300:
                    return recs
                try:
                    d = lg.data.struct
                    data = pe.get_data(d.OffsetToData, d.Size)
                except Exception:
                    continue
                if len(data) < 16:
                    continue
                sha = hashlib.sha256(data).hexdigest()
                if sha in seen:
                    continue
                seen.add(sha)
                outdir.mkdir(parents=True, exist_ok=True)
                name = safe_name(f"{tname}_{nname}_{getattr(lg, 'id', 0)}{carve.sniff(data)}")
                (outdir / name).write_bytes(data)
                recs.append({"name": name, "origin": f"resource {tname}/{nname}", "size": len(data), "sha256": sha})
    return recs


def _tls_callbacks(pe) -> list[int]:
    try:
        base = pe.OPTIONAL_HEADER.ImageBase
        ptr = 8 if pe.OPTIONAL_HEADER.Magic == 0x20B else 4
        off = pe.get_offset_from_rva(pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - base)
        res = []
        while len(res) < 32:
            v = int.from_bytes(pe.__data__[off:off + ptr], "little")
            if not v:
                break
            res.append(v - base)
            off += ptr
        return res
    except Exception:
        return []


def _pdata_funcs(pe) -> list[tuple[int, int]]:
    """x64 exception table (.pdata) = every non-leaf function start/size."""
    try:
        d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        if not d.VirtualAddress or pe.FILE_HEADER.Machine != 0x8664:
            return []
        data = pe.get_data(d.VirtualAddress, d.Size)
        out = []
        for i in range(0, len(data) - 11, 12):
            b, e, _ = struct.unpack_from("<III", data, i)
            if b and e > b:
                out.append((b, e - b))
        return out
    except Exception:
        return []


def pe_dump_sync(path: Path, out: Path, seen: set[str]) -> dict:
    import pefile
    out.mkdir(parents=True, exist_ok=True)
    stem = safe_name(path.stem)
    pe = pefile.PE(str(path))
    oh, fh = pe.OPTIONAL_HEADER, pe.FILE_HEADER
    dd = oh.DATA_DIRECTORY
    dotnet = len(dd) > 14 and dd[14].VirtualAddress != 0 and dd[14].Size != 0
    packers: list[str] = []
    L = [f"# {path.name}", f"size: {path.stat().st_size}", f"sha256: {_sha256(path)}",
         f"machine: {fh.Machine:#06x}   {'PE32+' if oh.Magic == 0x20B else 'PE32'}   dll: {pe.is_dll()}   .NET: {dotnet}",
         f"timestamp: {fh.TimeDateStamp}",
         f"imagebase: {oh.ImageBase:#x}   entry_rva: {oh.AddressOfEntryPoint:#x}   subsystem: {oh.Subsystem}"]
    try:
        L.append(f"imphash: {pe.get_imphash()}")
    except Exception:
        pass
    if hasattr(pe, "RICH_HEADER") and pe.RICH_HEADER:
        L.append("rich header: present (MSVC toolchain)")
    for d in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
        ent = getattr(d, "entry", None)
        if ent is not None and hasattr(ent, "PdbFileName"):
            L.append("pdb: " + ent.PdbFileName.rstrip(b"\0").decode(errors="ignore"))
    tls = _tls_callbacks(pe)
    if tls:
        L.append("tls callbacks (run before entry point): " + ", ".join(f"{x:#x}" for x in tls))
    if len(dd) > 4 and dd[4].VirtualAddress:
        L.append("authenticode signature: present")
    L += ["", "## sections"]
    for s in pe.sections:
        ent = s.get_entropy()
        nm = s.Name.rstrip(b"\0").decode(errors="ignore")
        if nm.lower() in PACKER_SECTIONS:
            packers.append(PACKER_SECTIONS[nm.lower()])
        L.append(f"{nm:<10} va={s.VirtualAddress:#010x} vsize={s.Misc_VirtualSize:#x} raw={s.SizeOfRawData:#x} "
                 f"entropy={ent:.2f}{'  <-- packed/encrypted?' if ent > 7.2 else ''}")
    packers = sorted(set(packers))
    if packers:
        L.append(f"packer/protector by section names: {', '.join(packers)}")
    funcs: dict[int, str] = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        L += ["", "## imports"]
        for e in pe.DIRECTORY_ENTRY_IMPORT:
            L.append(e.dll.decode(errors="ignore"))
            L += [f"    {i.name.decode(errors='ignore') if i.name else 'ord' + str(i.ordinal)}" for i in e.imports]
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        L += ["", "## exports  [rva name]"]
        for s in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            nm = s.name.decode(errors="ignore") if s.name else "ord" + str(s.ordinal)
            funcs[s.address] = nm
            L.append(f"{s.address:#010x} {nm}")
    try:
        for fi in pe.FileInfo:
            for e in fi:
                if hasattr(e, "StringTable"):
                    for st in e.StringTable:
                        L += ["", "## version info"] + [f"{k.decode(errors='ignore')}: {v.decode(errors='ignore')}" for k, v in st.entries.items()]
    except Exception:
        pass
    libs = detect_libs(path)
    L += ["", "## detected libraries / engines (by signatures)", *(libs or ["(nothing recognised)"])]

    pd = _pdata_funcs(pe)
    ep = oh.AddressOfEntryPoint
    flines = [f"{rva:#010x} {size:>8} {funcs.get(rva, 'EntryPoint' if rva == ep else f'sub_{rva:x}')}" for rva, size in sorted(set(pd))]
    if flines:
        (out / f"{stem}_functions.txt").write_text("rva size name   (from .pdata)\n" + "\n".join(flines), encoding="utf8")

    # ---- embedded files: resources, overlay, carved PE/zip/7z/png, base64 PE
    ext_dir = out / "extracted"
    recs = _pe_resources(pe, ext_dir, seen)
    size = path.stat().st_size
    ov = pe.get_overlay_data_start_offset()
    if ov and size - ov > 64:
        ext_dir.mkdir(exist_ok=True)
        tmp = ext_dir / "overlay.bin"
        h = hashlib.sha256()
        with open(path, "rb") as src, open(tmp, "wb") as dst:
            src.seek(ov)
            while chunk := src.read(1 << 20):
                h.update(chunk)
                dst.write(chunk)
        with open(tmp, "rb") as t:
            ext = carve.sniff(t.read(4096))
        final = ext_dir / ("overlay" + (ext if ext != ".bin" else ".bin"))
        if final != tmp:
            tmp.replace(final)
        if h.hexdigest() not in seen:
            seen.add(h.hexdigest())
            recs.append({"name": final.name, "origin": f"overlay @{ov:#x}", "size": size - ov, "sha256": h.hexdigest()})
        else:
            final.unlink()
    pe.close()
    recs += carve.carve(path, ext_dir, seen)

    (out / f"{stem}.txt").write_text("\n".join(L), encoding="utf8", errors="ignore")
    write_strings(_strings(path) + _strings(path, wide=True), out / f"{stem}_strings.txt")
    return {"dotnet": dotnet, "packers": packers, "libs": libs, "recs": recs, "funcs": len(flines)}


async def pe_full(path: Path, out: Path, notes: list[str], depth: int = 0, seen: set[str] | None = None) -> str:
    seen = seen if seen is not None else set()
    info = await asyncio.to_thread(pe_dump_sync, path, out, seen)
    kind = "Native PE"
    ext_dir = out / "extracted"
    if info["dotnet"]:
        kind = ".NET"
        try:
            await mono_dump(path, out / "dump.cs")
        except DumpError as e:
            notes.append(f"{path.name}: {e}")
        try:
            await ilspy_project(path, out / "project")
            info["recs"] += await asyncio.to_thread(costura_unpack, out / "project", ext_dir)
        except DumpError as e:
            notes.append(f"{path.name}: project export — {e}")
    if info["packers"]:
        notes.append(f"{path.name}: защищён ({', '.join(info['packers'])}) — статический дамп и извлечение ограничены")
    if info["libs"]:
        notes.append(f"{path.name}: " + "; ".join(info["libs"]))

    recs = info["recs"]
    if recs:
        ext_dir.mkdir(exist_ok=True)
        (ext_dir / "index.txt").write_text(
            "\n".join(f"{r['name']:<40} {r['size']:>10}  {r['origin']:<28} sha256={r['sha256']}" for r in recs), encoding="utf8")
    if depth < 1:                      # analyse extracted PE files one level deep
        for r in [r for r in recs if r["name"].lower().endswith((".dll", ".exe"))][:8]:
            try:
                await pe_full(ext_dir / r["name"], ext_dir / (Path(r["name"]).stem + "_dump"), notes, depth + 1, seen)
            except Exception as e:
                notes.append(f"{r['name']}: анализ не удался ({e})")
    libs_short = ", ".join(l.split("  <-")[0] for l in info["libs"][:4])
    return f"{kind} · извлечено файлов: {len(recs)}" + (f" · {libs_short}" if libs_short else "")


# ---- orchestration --------------------------------------------------------
def _engine(names: set[str]) -> str:
    for key, label in ENGINE_HINTS:
        if any(n.startswith(key) or key in n for n in names):
            return label
    return "неизвестный / свой движок"


async def _dump_archive(src: Path, work: Path, out: Path, pe: bool, notes: list[str]) -> str:
    ex = work / "x"
    ex.mkdir(exist_ok=True)
    f = Found()
    await asyncio.to_thread(scan, src, ex, f, 0, pe)
    if f.apks:
        lines = await asyncio.to_thread(apk_info, f.apks[0])
        if lines:
            (out / "manifest.txt").write_text("\n".join(lines), encoding="utf8")
    lib = _pick(f.il2cpp) or (f.gasm[0] if f.gasm else None)
    meta = max(f.meta, key=lambda p: p.stat().st_size) if f.meta else None
    engine = _engine(f.names)

    if lib and meta:
        await il2cpp_dump(lib, meta, out)
        return "Unity IL2CPP · Il2CppDumper"
    if lib and not meta:
        raise NeedMeta(lib)
    if meta and not lib and not f.managed:
        raise NeedLib(meta)

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
        libs = sorted((p for a, p in f.native if a == best), key=lambda p: p.stat().st_size, reverse=True)[:16]
        for p in libs:
            name = p.name.split("_", 1)[-1]
            notes.append(await asyncio.to_thread(elf_dump, p, out / "native" / name))
        return f"{engine} · native ELF ({best}, {len(libs)} lib): symbols / functions / strings"

    if pe and f.pe:
        reps = [await pe_full(p, out / safe_name(p.stem.split("_", 1)[-1]), notes) for p in f.pe]
        return reps[0] if len(reps) == 1 else f"PE · {len(reps)} exe"
    raise DumpError("не нашёл ни il2cpp, ни Mono-сборок, ни нативных библиотек")


def pick_from_zip(path: Path, dest: Path, want: str, pe: bool) -> Path | None:
    """Pull global-metadata.dat (want='meta') or libil2cpp.so / GameAssembly.dll (want='lib') out of a zip/apk/xapk."""
    dest.m                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       