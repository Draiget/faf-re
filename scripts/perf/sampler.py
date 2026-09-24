"""Poor-man's sampling profiler for the 32-bit ForgedAlliance.exe (WOW64).

Suspends each busy thread briefly, reads its WOW64 context and a slice of its
stack, and aggregates:
  flat[(tid, leaf)]            leaf function per sample
  incl[(tid, func)]            each function once per sample (heuristic stack scan)
  edge[(tid, caller, callee)]  consecutive distinct stack functions (heuristic)
Return-address candidates are stack dwords inside .text whose preceding bytes
decode as a CALL, so stale locals are mostly filtered out.

Also locates the Sim object (vtable 0x00E34714) by heap scan and records
mCurTick (+0x900) and the entity count (*(Sim+0x984)+8) per window.

usage: sampler.py <pid> <outdir> <seconds> [window_seconds]

Tables come from build_symbols.py (env FAF_PERF_TABLES, default %TEMP%/faf_perf).
The target exe defaults to FAF's ForgedAlliance.exe (env FA_EXE), which must be the
binary the fa_full_2026_03_26 export was made from.
"""
import bisect
import collections
import ctypes
import ctypes.wintypes as wt
import json
import os
import struct
import sys
import time

EXE = os.environ.get("FA_EXE", r"C:\ProgramData\FAForever\bin\ForgedAlliance.exe")
TABLES = os.environ.get("FAF_PERF_TABLES", os.path.join(os.environ.get("TEMP", "."), "faf_perf"))
SYMMAP = os.path.join(TABLES, "symmap.json")
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CALLGRAPH = os.path.join(REPO, "decomp", "recovery", "disasm", "fa_full_2026_03_26", "_callgraph_index.sqlite")
SIM_VTABLE = 0x00E34714

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
winmm = ctypes.WinDLL("winmm")

TH32CS_SNAPTHREAD = 0x4
TH32CS_SNAPMODULE = 0x8
TH32CS_SNAPMODULE32 = 0x10
THREAD_ACCESS = 0x0002 | 0x0008 | 0x0040  # SUSPEND_RESUME | GET_CONTEXT | QUERY_INFORMATION
PROCESS_ACCESS = 0x0010 | 0x0400  # VM_READ | QUERY_INFORMATION


class THREADENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ThreadID", wt.DWORD),
                ("th32OwnerProcessID", wt.DWORD), ("tpBasePri", wt.LONG), ("tpDeltaPri", wt.LONG),
                ("dwFlags", wt.DWORD)]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("th32ModuleID", wt.DWORD), ("th32ProcessID", wt.DWORD),
                ("GlblcntUsage", wt.DWORD), ("ProccntUsage", wt.DWORD), ("modBaseAddr", ctypes.c_void_p),
                ("modBaseSize", wt.DWORD), ("hModule", wt.HMODULE), ("szModule", wt.WCHAR * 256),
                ("szExePath", wt.WCHAR * 260)]


class WOW64_FLOATING_SAVE_AREA(ctypes.Structure):
    _fields_ = [("ControlWord", wt.DWORD), ("StatusWord", wt.DWORD), ("TagWord", wt.DWORD),
                ("ErrorOffset", wt.DWORD), ("ErrorSelector", wt.DWORD), ("DataOffset", wt.DWORD),
                ("DataSelector", wt.DWORD), ("RegisterArea", ctypes.c_ubyte * 80), ("Cr0NpxState", wt.DWORD)]


class WOW64_CONTEXT(ctypes.Structure):
    _fields_ = [("ContextFlags", wt.DWORD), ("Dr0", wt.DWORD), ("Dr1", wt.DWORD), ("Dr2", wt.DWORD),
                ("Dr3", wt.DWORD), ("Dr6", wt.DWORD), ("Dr7", wt.DWORD), ("FloatSave", WOW64_FLOATING_SAVE_AREA),
                ("SegGs", wt.DWORD), ("SegFs", wt.DWORD), ("SegEs", wt.DWORD), ("SegDs", wt.DWORD),
                ("Edi", wt.DWORD), ("Esi", wt.DWORD), ("Ebx", wt.DWORD), ("Edx", wt.DWORD), ("Ecx", wt.DWORD),
                ("Eax", wt.DWORD), ("Ebp", wt.DWORD), ("Eip", wt.DWORD), ("SegCs", wt.DWORD),
                ("EFlags", wt.DWORD), ("Esp", wt.DWORD), ("SegSs", wt.DWORD),
                ("ExtendedRegisters", ctypes.c_ubyte * 512)]


WOW64_CONTEXT_CONTROL_INTEGER = 0x00010000 | 0x1 | 0x2


class FILETIME(ctypes.Structure):
    _fields_ = [("lo", wt.DWORD), ("hi", wt.DWORD)]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD), ("PartitionId", wt.WORD), ("RegionSize", ctypes.c_size_t),
                ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]


k32.OpenThread.restype = wt.HANDLE
k32.OpenProcess.restype = wt.HANDLE
k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
k32.Wow64SuspendThread.restype = wt.DWORD
k32.ResumeThread.restype = wt.DWORD
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]
k32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
k32.VirtualQueryEx.restype = ctypes.c_size_t


def load_text_section(path):
    data = open(path, "rb").read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    image_base = struct.unpack_from("<I", data, pe + 24 + 28)[0]
    sec = pe + 24 + opt_size
    image = {}
    for i in range(nsec):
        name, vsize, va, rsize, rptr = struct.unpack_from("<8sIIII", data, sec + i * 40)
        image[name.rstrip(b"\0").decode()] = (image_base + va, vsize, data[rptr:rptr + rsize])
    return image


IMAGE = load_text_section(EXE)
TEXT_VA, TEXT_SIZE, TEXT_BYTES = IMAGE[".text"]
TEXT_END = TEXT_VA + TEXT_SIZE


def text_byte(addr):
    off = addr - TEXT_VA
    if 0 <= off < len(TEXT_BYTES):
        return TEXT_BYTES[off]
    return None


def is_call_return(addr):
    """True if the bytes before addr decode as a CALL instruction."""
    if not (TEXT_VA + 7 <= addr < TEXT_END):
        return False
    b = lambda d: text_byte(addr - d) or 0
    if b(5) == 0xE8:                                   # call rel32
        return True
    if b(6) == 0xFF and b(5) in (0x15,) or (b(6) == 0xFF and (b(5) & 0x38) == 0x10 and (b(5) >> 6) == 2):
        return True                                    # call [disp32] / call [reg+disp32]
    if b(2) == 0xFF and (b(1) & 0x38) == 0x10 and (b(1) >> 6) in (0, 3):
        return True                                    # call reg / call [reg]
    if b(3) == 0xFF and (b(2) & 0x38) == 0x10 and (b(2) >> 6) == 1:
        return True                                    # call [reg+disp8]
    if b(3) == 0xFF and (b(2) & 0x38) == 0x10 and (b(2) & 7) == 4 and (b(2) >> 6) == 0:
        return True                                    # call [sib]
    if b(4) == 0xFF and (b(3) & 0x38) == 0x10 and (b(3) & 7) == 4 and (b(3) >> 6) == 1:
        return True                                    # call [sib+disp8]
    if b(7) == 0xFF and (b(6) & 0x38) == 0x10 and (b(6) & 7) == 4 and (b(6) >> 6) == 2:
        return True                                    # call [sib+disp32]
    return False


SYM = json.load(open(SYMMAP))
STARTS = [r[0] for r in SYM]
START_INDEX = {r[0]: i for i, r in enumerate(SYM)}


def func_index(addr):
    i = bisect.bisect_right(STARTS, addr) - 1
    if i >= 0 and SYM[i][0] <= addr < SYM[i][1]:
        return i
    return -1


def load_call_validation():
    """addr_taken: functions reachable by an indirect call (their address is stored as data).
    tail_dests[f]: functions that f leaves through an E9 jmp (tail call)."""
    import sqlite3
    db = sqlite3.connect(CALLGRAPH)
    tok_index = {r[2]: i for i, r in enumerate(SYM)}
    taken = set()
    for (tok,) in db.execute("select distinct to_token from data_refs where to_token like 'FUN_%'"):
        if tok in tok_index:
            taken.add(tok_index[tok])
    for (tok,) in db.execute("select distinct target_token from incoming_xrefs where kind='data'"):
        if tok in tok_index:
            taken.add(tok_index[tok])
    tails = collections.defaultdict(set)
    off = 0
    while True:
        off = TEXT_BYTES.find(b"\xE9", off)
        if off < 0 or off + 5 > len(TEXT_BYTES):
            break
        src = TEXT_VA + off
        dst = (src + 5 + struct.unpack_from("<i", TEXT_BYTES, off + 1)[0]) & 0xFFFFFFFF
        di = START_INDEX.get(dst)
        if di is not None:
            si = func_index(src)
            if si >= 0 and si != di:
                tails[si].add(di)
        off += 1
    return taken, tails


ADDR_TAKEN, TAIL_DESTS = load_call_validation()


def load_return_sites():
    """Exact return addresses of every call instruction in the disassembly export:
    ret -> ('d', target) direct, ('i', None) through the import table, ('x', None) other indirect."""
    import re
    sites = {}
    pat = re.compile(r"^0x([0-9A-Fa-f]{8}): ((?:[0-9A-F]{2} )+)\s*call\s+(.*)$")
    for line in open(os.path.join(TABLES, "callsites.txt")):
        m = pat.match(line.strip())
        if not m:
            continue
        addr = int(m.group(1), 16)
        size = len(m.group(2).split())
        operand = m.group(3)
        ret = addr + size
        if operand.startswith("0x"):
            sites[ret] = ("d", int(operand.split()[0], 16))
        elif "ptr [0x" in operand and IAT_LO <= int(operand.split("[0x")[1].split("]")[0], 16) < IAT_HI:
            sites[ret] = ("i", None)
        else:
            sites[ret] = ("x", None)
    return sites


def iat_range(path):
    data = open(path, "rb").read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    image_base = struct.unpack_from("<I", data, pe + 24 + 28)[0]
    rva, size = struct.unpack_from("<II", data, pe + 24 + 96 + 12 * 8)  # data directory 12 = IAT
    return image_base + rva, image_base + rva + size


IAT_LO, IAT_HI = iat_range(EXE)
RET_SITES = load_return_sites()


def accepts(ret, cur):
    """Is the real call site that returns to `ret` a plausible caller of function `cur`?"""
    site = RET_SITES.get(ret)
    if site is None:
        return False
    kind, tgt = site
    if kind == "i":
        return cur < 0
    if kind == "x":
        return cur < 0 or cur in ADDR_TAKEN
    ti = func_index(tgt)
    if cur < 0:
        return ti >= 0 and (SYM[ti][1] - SYM[ti][0]) <= 16  # exe thunk jumping into a DLL
    if ti == cur:
        return True
    if ti < 0:
        return False
    if cur in TAIL_DESTS.get(ti, ()):
        return True
    return (SYM[ti][1] - SYM[ti][0]) <= 16  # tiny forwarding thunk


def modules(pid):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    me = MODULEENTRY32W()
    me.dwSize = ctypes.sizeof(me)
    mods = []
    ok = k32.Module32FirstW(snap, ctypes.byref(me))
    while ok:
        mods.append((me.modBaseAddr or 0, (me.modBaseAddr or 0) + me.modBaseSize, me.szModule))
        ok = k32.Module32NextW(snap, ctypes.byref(me))
    k32.CloseHandle(snap)
    mods.sort()
    return mods


def threads(pid):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    te = THREADENTRY32()
    te.dwSize = ctypes.sizeof(te)
    out = []
    ok = k32.Thread32First(snap, ctypes.byref(te))
    while ok:
        if te.th32OwnerProcessID == pid:
            out.append(te.th32ThreadID)
        ok = k32.Thread32Next(snap, ctypes.byref(te))
    k32.CloseHandle(snap)
    return out


def thread_cpu(h):
    c, e, kt, ut = FILETIME(), FILETIME(), FILETIME(), FILETIME()
    if not k32.GetThreadTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(kt), ctypes.byref(ut)):
        return None
    return ((kt.hi << 32) | kt.lo) + ((ut.hi << 32) | ut.lo)


def rpm(hp, addr, size):
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t(0)
    if k32.ReadProcessMemory(hp, ctypes.c_void_p(addr), buf, size, ctypes.byref(got)) and got.value:
        return buf.raw[:got.value]
    return None


def find_sim(hp):
    """Scan committed private RW memory for an object whose first dword is the Sim vtable
    and whose mCurTick / mEntityDB look sane."""
    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0x10000
    needle = struct.pack("<I", SIM_VTABLE)
    cands = []
    while addr < 0xFFFF0000:
        if not k32.VirtualQueryEx(hp, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize
        if mbi.State == 0x1000 and mbi.Type == 0x20000 and mbi.Protect in (0x04, 0x40):  # MEM_COMMIT, MEM_PRIVATE, RW
            data = rpm(hp, base, size)
            if data:
                i = data.find(needle)
                while i >= 0:
                    if i % 4 == 0:
                        cands.append(base + i)
                    i = data.find(needle, i + 1)
        addr = base + size
    for c in cands:
        blob = rpm(hp, c, 0x990)
        if not blob or len(blob) < 0x988:
            continue
        tick = struct.unpack_from("<I", blob, 0x900)[0]
        edb = struct.unpack_from("<I", blob, 0x984)[0]
        if edb and tick < 10_000_000:
            return c
    return None


def sim_state(hp, sim):
    blob = rpm(hp, sim, 0x988)
    if not blob:
        return None
    beat, = struct.unpack_from("<I", blob, 0x8F8)
    tick, = struct.unpack_from("<I", blob, 0x900)
    edb, = struct.unpack_from("<I", blob, 0x984)
    count = None
    families = {}
    if edb:
        m = rpm(hp, edb, 12)
        if m:
            count = struct.unpack_from("<I", m, 8)[0]
            families = entity_census(hp, struct.unpack_from("<I", m, 4)[0])
    return {"beat": beat, "tick": tick, "entities": count, "families": families}


FAMILY_NAMES = {0: "unit", 1: "projectile", 2: "prop", 3: "blip", 4: "shield", 5: "other"}


def entity_census(hp, head):
    """Walk Sim::mEntityDB->mAllUnits (msvc8 map<EntId, Entity*>, node 0x18: left/parent/right,
    key +0x0C, value +0x10, isnil +0x15) and count ids by family (id >> 28). Racy but read-only."""
    hb = rpm(hp, head, 0x18)
    if not hb:
        return {}
    root = struct.unpack_from("<I", hb, 4)[0]
    counts = collections.Counter()
    todo, seen = [root], set()
    while todo and len(seen) < 300000:
        n = todo.pop()
        if not n or n == head or n in seen:
            continue
        seen.add(n)
        nb = rpm(hp, n, 0x18)
        if not nb or nb[0x15]:
            continue
        left, _parent, right, key = struct.unpack_from("<4I", nb, 0)
        counts[FAMILY_NAMES.get(key >> 28, str(key >> 28))] += 1
        todo.append(left)
        todo.append(right)
    return dict(counts)


def main():
    pid = int(sys.argv[1])
    outdir = sys.argv[2]
    duration = float(sys.argv[3])
    window = float(sys.argv[4]) if len(sys.argv) > 4 else 60.0
    os.makedirs(outdir, exist_ok=True)
    winmm.timeBeginPeriod(1)
    hp = k32.OpenProcess(PROCESS_ACCESS, False, pid)
    if not hp:
        raise SystemExit("OpenProcess failed %d" % ctypes.get_last_error())
    mods = modules(pid)
    mod_starts = [m[0] for m in mods]

    def module_of(addr):
        i = bisect.bisect_right(mod_starts, addr) - 1
        if i >= 0 and mods[i][0] <= addr < mods[i][1]:
            return mods[i][2]
        return "?"

    handles = {}
    last_cpu = {}
    busy = []
    sim = None
    t0 = time.time()
    next_refresh = 0
    next_sim_scan = 0
    next_dump = t0 + window
    win_idx = 0
    flat = collections.Counter()
    incl = collections.Counter()
    edge = collections.Counter()
    samples = collections.Counter()
    chains = collections.Counter()
    stack_top = {}
    smbi = MEMORY_BASIC_INFORMATION()
    ctx = WOW64_CONTEXT()
    cpu_window = collections.Counter()
    win_start_state = None
    while time.time() - t0 < duration:
        now = time.time()
        if now >= next_refresh:
            next_refresh = now + 1.0
            for tid in threads(pid):
                if tid not in handles:
                    h = k32.OpenThread(THREAD_ACCESS, False, tid)
                    if h:
                        handles[tid] = h
            usage = []
            for tid, h in list(handles.items()):
                c = thread_cpu(h)
                if c is None:
                    k32.CloseHandle(h)
                    del handles[tid]
                    continue
                d = c - last_cpu.get(tid, c)
                last_cpu[tid] = c
                cpu_window[tid] += d
                usage.append((d, tid))
            usage.sort(reverse=True)
            busy = [tid for d, tid in usage[:4] if d > 1_000_000]  # >10% of a core over the last second
            if sim is None and now >= next_sim_scan:
                next_sim_scan = now + 15.0
                sim = find_sim(hp)
                if sim:
                    print("Sim object at 0x%08X" % sim, flush=True)
            if win_start_state is None and sim:
                win_start_state = sim_state(hp, sim)
        for tid in busy:
            h = handles.get(tid)
            if not h:
                continue
            if k32.Wow64SuspendThread(h) == 0xFFFFFFFF:
                continue
            try:
                ctx.ContextFlags = WOW64_CONTEXT_CONTROL_INTEGER
                ok = k32.Wow64GetThreadContext(h, ctypes.byref(ctx))
                stack = None
                if ok:
                    # Read only up to the end of the committed stack region holding ESP; a fixed-size
                    # read past the stack base fails as a partial copy and loses the whole chain.
                    top = stack_top.get(tid)
                    if top is None or not (ctx.Esp < top <= ctx.Esp + 0x100000):
                        if k32.VirtualQueryEx(hp, ctypes.c_void_p(ctx.Esp), ctypes.byref(smbi), ctypes.sizeof(smbi)):
                            top = (smbi.BaseAddress or 0) + smbi.RegionSize
                            stack_top[tid] = top
                    if top:
                        stack = rpm(hp, ctx.Esp, max(4, min(32768, top - ctx.Esp)))
            finally:
                k32.ResumeThread(h)
            if not ok:
                continue
            eip = ctx.Eip
            leaf = func_index(eip)
            leaf_key = leaf if leaf >= 0 else ("mod:" + module_of(eip))
            samples[tid] += 1
            flat[(tid, leaf_key)] += 1
            chain = [leaf_key]
            if stack:
                n = len(stack) // 4
                cur = leaf
                for (v,) in struct.iter_unpack("<I", stack[: n * 4]):
                    if v in RET_SITES:
                        fi = func_index(v)
                        if fi >= 0 and accepts(v, cur):
                            if fi != chain[-1]:
                                chain.append(fi)
                            cur = fi
            seen = set()
            for f in chain:
                if f not in seen:
                    seen.add(f)
                    incl[(tid, f)] += 1
            for a, b in zip(chain[1:], chain[:-1]):
                edge[(tid, a, b)] += 1
            chains[(tid, tuple(chain[:48]))] += 1
        time.sleep(0.001)
        if time.time() >= next_dump:
            state = sim_state(hp, sim) if sim else None
            dump = {
                "window": win_idx, "t": time.time() - t0, "sim_start": win_start_state, "sim_end": state,
                "cpu_100ns": {str(k): v for k, v in cpu_window.items()},
                "samples": {str(k): v for k, v in samples.items()},
                "flat": [[t, k, v] for (t, k), v in flat.most_common(4000)],
                "incl": [[t, k, v] for (t, k), v in incl.most_common(8000)],
                "edge": [[t, a, b, v] for (t, a, b), v in edge.most_common(20000)],
                "chains": [[t, list(c), v] for (t, c), v in chains.most_common(60000)],
            }
            with open(os.path.join(outdir, "win_%03d.json" % win_idx), "w") as fh:
                json.dump(dump, fh)
            print("window %d t=%.0fs samples=%s sim=%s" % (win_idx, dump["t"], dict(samples), state), flush=True)
            win_idx += 1
            next_dump = time.time() + window
            flat.clear(); incl.clear(); edge.clear(); samples.clear(); cpu_window.clear(); chains.clear()
            win_start_state = state
    winmm.timeEndPeriod(1)


if __name__ == "__main__":
    main()
