"""Sampling profiler for the native x64 rebuilt engine (main_x64.exe).

usage: python scripts/perf/sampler64.py <pid> <symdir> <outdir> <duration_s> [window_s] [hz]

  <pid>        the running main_x64.exe
  <symdir>     folder holding the PDB that matches the running exe (dbghelp searches it; copy the
               exe's PDB aside before rebuilding, the build overwrites it)
  <outdir>     receives one win_NNN.json per window (default window 60 s, default 250 Hz)

Must run under a 64-bit Python. x64 code carries exact unwind data (.pdata/.xdata), so dbghelp's
StackWalk64 gives exact call chains, unlike the stack scan sampler.py has to do for the 32-bit
exe. Each busy thread (more than 10% of a core over the last second, top 6) is suspended only
long enough to copy its context and stack; the walk then runs on the copy. Samples are taken on
wall-clock time, so waits count: a thread's waits show up as leaf frames such as
ntdll.dll!NtWaitForSingleObject.

Each window holds:
  cpu_100ns {tid: cpu}, samples {tid: n}, names [..],
  flat [[tid, nameidx, n]], incl [[tid, nameidx, n]], chains [[tid, [nameidx leaf..root], n]],
  joint [[[busy tids], n]] and cond [[tid, busy, other_tid, nameidx, n]]: what each sampled
  thread was doing while another one was busy or waiting (see joint.py),
  sim_start / sim_end {tick, beat, entities, families} read from the live Sim object (located by
  its vtable, member offsets from the PDB).

Analyse with prof64.py and joint.py next to this file.
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

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
dbg = ctypes.WinDLL("dbghelp", use_last_error=True)
winmm = ctypes.WinDLL("winmm")

PROCESS_ACCESS = 0x00100000 | 0x0400 | 0x0010 | 0x0008 | 0x0020  # QUERY_INFORMATION | VM_READ | VM_OPERATION | VM_WRITE
THREAD_ACCESS = 0x0002 | 0x0008 | 0x0010 | 0x0040  # SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT | QUERY_INFORMATION
TH32CS_SNAPTHREAD, TH32CS_SNAPMODULE = 0x4, 0x8
CONTEXT_AMD64 = 0x00100000
CONTEXT_FULL = CONTEXT_AMD64 | 0x1 | 0x2 | 0x8


class FILETIME(ctypes.Structure):
    _fields_ = [("lo", wt.DWORD), ("hi", wt.DWORD)]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ThreadID", wt.DWORD),
                ("th32OwnerProcessID", wt.DWORD), ("tpBasePri", wt.LONG), ("tpDeltaPri", wt.LONG),
                ("dwFlags", wt.DWORD)]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("th32ModuleID", wt.DWORD), ("th32ProcessID", wt.DWORD),
                ("GlblcntUsage", wt.DWORD), ("ProccntUsage", wt.DWORD), ("modBaseAddr", ctypes.c_void_p),
                ("modBaseSize", wt.DWORD), ("hModule", wt.HMODULE), ("szModule", wt.WCHAR * 256),
                ("szExePath", wt.WCHAR * 260)]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD), ("PartitionId", wt.WORD), ("RegionSize", ctypes.c_size_t),
                ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]


class ADDRESS64(ctypes.Structure):
    _fields_ = [("Offset", ctypes.c_uint64), ("Segment", wt.WORD), ("Mode", ctypes.c_int)]


class STACKFRAME64(ctypes.Structure):
    _fields_ = [("AddrPC", ADDRESS64), ("AddrReturn", ADDRESS64), ("AddrFrame", ADDRESS64),
                ("AddrStack", ADDRESS64), ("AddrBStore", ADDRESS64), ("FuncTableEntry", ctypes.c_void_p),
                ("Params", ctypes.c_uint64 * 4), ("Far", wt.BOOL), ("Virtual", wt.BOOL),
                ("Reserved", ctypes.c_uint64 * 3), ("KdHelp", ctypes.c_byte * 512)]


class SYMBOL_INFOW(ctypes.Structure):
    _fields_ = [("SizeOfStruct", wt.ULONG), ("TypeIndex", wt.ULONG), ("Reserved", ctypes.c_uint64 * 2),
                ("Index", wt.ULONG), ("Size", wt.ULONG), ("ModBase", ctypes.c_uint64), ("Flags", wt.ULONG),
                ("Value", ctypes.c_uint64), ("Address", ctypes.c_uint64), ("Register", wt.ULONG),
                ("Scope", wt.ULONG), ("Tag", wt.ULONG), ("NameLen", wt.ULONG), ("MaxNameLen", wt.ULONG),
                ("Name", wt.WCHAR * 1024)]


READ_MEM = ctypes.WINFUNCTYPE(wt.BOOL, wt.HANDLE, ctypes.c_uint64, ctypes.c_void_p, wt.DWORD,
                              ctypes.POINTER(wt.DWORD))
dbg.StackWalk64.argtypes = [wt.DWORD, wt.HANDLE, wt.HANDLE, ctypes.POINTER(STACKFRAME64), ctypes.c_void_p,
                            READ_MEM, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
dbg.SymInitializeW.argtypes = [wt.HANDLE, wt.LPCWSTR, wt.BOOL]
dbg.SymFromAddrW.argtypes = [wt.HANDLE, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(SYMBOL_INFOW)]
dbg.SymFromNameW.argtypes = [wt.HANDLE, wt.LPCWSTR, ctypes.POINTER(SYMBOL_INFOW)]
dbg.SymGetModuleBase64.argtypes = [wt.HANDLE, ctypes.c_uint64]
dbg.SymGetModuleBase64.restype = ctypes.c_uint64
dbg.SymGetTypeFromNameW.argtypes = [wt.HANDLE, ctypes.c_uint64, wt.LPCWSTR, ctypes.POINTER(SYMBOL_INFOW)]
dbg.SymGetTypeInfo.argtypes = [wt.HANDLE, ctypes.c_uint64, wt.ULONG, ctypes.c_int, ctypes.c_void_p]
dbg.SymRefreshModuleList.argtypes = [wt.HANDLE]
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]
k32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.GetThreadContext.argtypes = [wt.HANDLE, ctypes.c_void_p]
k32.OpenThread.restype = wt.HANDLE
k32.OpenProcess.restype = wt.HANDLE
k32.CreateToolhelp32Snapshot.restype = wt.HANDLE

# CONTEXT (AMD64) is 0x4D0 bytes and must be 16-byte aligned.
_ctx_raw = ctypes.create_string_buffer(0x4D0 + 16)
CTX = (ctypes.addressof(_ctx_raw) + 15) & ~15
OFF_FLAGS, OFF_RSP, OFF_RIP = 0x30, 0x98, 0xF8


def rpm(hp, addr, size):
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t(0)
    if k32.ReadProcessMemory(hp, ctypes.c_void_p(addr), buf, size, ctypes.byref(got)) and got.value:
        return buf.raw[:got.value]
    return None


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


def modules(pid):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
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


def thread_cpu(h):
    c, e, kt, ut = FILETIME(), FILETIME(), FILETIME(), FILETIME()
    if not k32.GetThreadTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(kt), ctypes.byref(ut)):
        return None
    return ((kt.hi << 32) | kt.lo) + ((ut.hi << 32) | ut.lo)


def member_offsets(hp, base, type_name):
    """{member name: offset} of a UDT from the PDB (direct members only)."""
    si = SYMBOL_INFOW()
    si.SizeOfStruct = 88
    si.MaxNameLen = 1024
    if not dbg.SymGetTypeFromNameW(hp, base, type_name, ctypes.byref(si)):
        return {}
    tid = si.TypeIndex
    count = wt.DWORD(0)
    if not dbg.SymGetTypeInfo(hp, base, tid, 13, ctypes.byref(count)):  # TI_GET_CHILDRENCOUNT
        return {}
    buf = (wt.ULONG * (2 + count.value))()
    buf[0] = count.value
    buf[1] = 0
    if not dbg.SymGetTypeInfo(hp, base, tid, 7, buf):  # TI_FINDCHILDREN
        return {}
    out = {}
    for i in range(count.value):
        child = buf[2 + i]
        name_p = ctypes.c_void_p()
        off = wt.DWORD(0)
        if dbg.SymGetTypeInfo(hp, base, child, 1, ctypes.byref(name_p)) and name_p.value:  # TI_GET_SYMNAME
            name = ctypes.wstring_at(name_p.value)
            k32.LocalFree(name_p)
            if dbg.SymGetTypeInfo(hp, base, child, 10, ctypes.byref(off)):  # TI_GET_OFFSET
                out[name] = off.value
    return out


def main():
    pid = int(sys.argv[1])
    symdir = sys.argv[2]
    outdir = sys.argv[3]
    duration = float(sys.argv[4])
    window = float(sys.argv[5]) if len(sys.argv) > 5 else 60.0
    hz = float(sys.argv[6]) if len(sys.argv) > 6 else 250.0
    os.makedirs(outdir, exist_ok=True)
    winmm.timeBeginPeriod(1)
    hp = k32.OpenProcess(PROCESS_ACCESS, False, pid)
    if not hp:
        raise SystemExit("OpenProcess failed %d" % ctypes.get_last_error())
    dbg.SymSetOptions(0x2 | 0x4)  # UNDNAME | DEFERRED_LOADS
    if not dbg.SymInitializeW(hp, symdir, True):
        raise SystemExit("SymInitialize failed %d" % ctypes.get_last_error())
    mods = modules(pid)
    mod_starts = [m[0] for m in mods]
    exe = next(m for m in mods if m[2].lower().endswith(".exe"))
    print("exe %s at 0x%X" % (exe[2], exe[0]), flush=True)

    si = SYMBOL_INFOW()

    def sym_reset():
        si.SizeOfStruct = 88
        si.MaxNameLen = 1024

    # Sim object: scan private RW memory for the Sim vtable, then read tick/beat/entity DB.
    sim_off = member_offsets(hp, exe[0], "moho::Sim")
    edb_off = member_offsets(hp, exe[0], "moho::EntityDB")
    print("Sim offsets:", {k: hex(v) for k, v in sim_off.items() if k in ("mCurTick", "mCurBeat", "mEntityDB")},
          "EntityDB:", {k: hex(v) for k, v in list(edb_off.items())[:4]}, flush=True)
    sym_reset()
    sim_vtable = None
    for nm in ("moho::Sim::`vftable'",):
        if dbg.SymFromNameW(hp, nm, ctypes.byref(si)):
            sim_vtable = si.Address
    print("Sim vtable", hex(sim_vtable) if sim_vtable else None, flush=True)

    def find_sim():
        if not sim_vtable or "mCurTick" not in sim_off:
            return None
        needle = struct.pack("<Q", sim_vtable)
        mbi = MEMORY_BASIC_INFORMATION()
        addr = 0x10000
        while addr < 0x7FFFFFFF0000:
            if not k32.VirtualQueryEx(hp, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                break
            base = mbi.BaseAddress or 0
            size = mbi.RegionSize
            if mbi.State == 0x1000 and mbi.Type == 0x20000 and mbi.Protect in (0x04, 0x40) and size < (1 << 30):
                data = rpm(hp, base, size)
                if data:
                    i = data.find(needle)
                    while i >= 0:
                        if i % 8 == 0:
                            c = base + i
                            blob = rpm(hp, c + sim_off["mCurTick"], 4)
                            if blob and struct.unpack("<I", blob)[0] < 10_000_000:
                                return c
                        i = data.find(needle, i + 1)
            addr = base + size
        return None

    units_map_off = edb_off.get("mAllUnits")

    def sim_state(sim):
        tick = rpm(hp, sim + sim_off["mCurTick"], 4)
        beat = rpm(hp, sim + sim_off.get("mCurBeat", sim_off["mCurTick"]), 4)
        if not tick:
            return None
        st = {"tick": struct.unpack("<I", tick)[0], "beat": struct.unpack("<I", beat)[0]}
        edb = rpm(hp, sim + sim_off["mEntityDB"], 8) if "mEntityDB" in sim_off else None
        if edb and units_map_off is not None:
            edb = struct.unpack("<Q", edb)[0]
            m = rpm(hp, edb + units_map_off, 24)
            if m:
                # msvc8::map under pack(4): {proxy, _Myhead, _Mysize}; the header node has _Isnil set.
                nonlocal NIL_OFF
                for hoff, nil in ((8, 0x29), (8, 0x25), (4, 0x25), (4, 0x29)):
                    head, size = struct.unpack_from("<QI", m, hoff)
                    hb = rpm(hp, head, 0x30) if head else None
                    if not hb or hb[nil] != 1:
                        continue
                    rb = rpm(hp, struct.unpack_from("<Q", hb, 8)[0], 0x30)
                    if rb and rb[nil] == 0:
                        NIL_OFF = nil
                        st["entities"] = size
                        st["families"] = census(head)
                        break
        return st

    # Node: left/parent/right (8 each), pair<uint32, Entity*> packed to 4 (12 bytes), color, isnil.
    NIL_OFF = 0x25
    names_fam = {0: "unit", 1: "projectile", 2: "prop", 3: "blip", 4: "shield", 5: "other"}

    def census(head):
        hb = rpm(hp, head, 0x30)
        if not hb:
            return {}
        root = struct.unpack_from("<Q", hb, 8)[0]
        counts = collections.Counter()
        todo, seen = [root], set()
        while todo and len(seen) < 400000:
            n = todo.pop()
            if not n or n == head or n in seen:
                continue
            seen.add(n)
            nb = rpm(hp, n, 0x30)
            if not nb or nb[NIL_OFF]:
                continue
            left, _p, right = struct.unpack_from("<3Q", nb, 0)
            key = struct.unpack_from("<I", nb, 0x18)[0]
            counts[names_fam.get(key >> 28, str(key >> 28))] += 1
            todo.append(left)
            todo.append(right)
        return dict(counts)

    # Symbolization with a per-address cache; names are interned into one list per run.
    names, name_idx, addr_cache = [], {}, {}
    wait_ids = set()
    WAIT_MARKERS = ("NtWaitFor", "ZwWaitFor", "NtDelayExecution", "WaitForAlertByThreadId", "NtUserMsgWaitFor",
                    "NtRemoveIoCompletion", "NtUserWaitMessage")

    def intern(n):
        i = name_idx.get(n)
        if i is None:
            i = name_idx[n] = len(names)
            names.append(n)
            if any(x in n for x in WAIT_MARKERS):
                wait_ids.add(i)
        return i

    def func_of(addr):
        r = addr_cache.get(addr)
        if r is not None:
            return r
        sym_reset()
        disp = ctypes.c_uint64(0)
        if dbg.SymFromAddrW(hp, addr, ctypes.byref(disp), ctypes.byref(si)):
            n = ctypes.wstring_at(ctypes.addressof(si) + SYMBOL_INFOW.Name.offset, si.NameLen)
            i = bisect.bisect_right(mod_starts, addr) - 1
            if not (exe[0] <= addr < exe[1]) and i >= 0:
                n = mods[i][2] + "!" + n
        else:
            i = bisect.bisect_right(mod_starts, addr) - 1
            n = ("mod:" + mods[i][2]) if i >= 0 and mods[i][0] <= addr < mods[i][1] else "?"
        r = addr_cache[addr] = intern(n)
        return r

    # Stack copy served to StackWalk64; everything else is read live (code, unwind data).
    snap = {"lo": 0, "data": b""}

    @READ_MEM
    def read_mem(_h, addr, buf, size, nread):
        lo = snap["lo"]
        data = snap["data"]
        if lo <= addr and addr + size <= lo + len(data):
            ctypes.memmove(buf, data[addr - lo: addr - lo + size], size)
            if nread:
                nread[0] = size
            return True
        got = ctypes.c_size_t(0)
        ok = k32.ReadProcessMemory(hp, ctypes.c_void_p(addr), ctypes.c_void_p(buf), size, ctypes.byref(got))
        if nread:
            nread[0] = got.value
        return bool(ok) and got.value == size

    fta = ctypes.cast(dbg.SymFunctionTableAccess64, ctypes.c_void_p)
    gmb = ctypes.cast(dbg.SymGetModuleBase64, ctypes.c_void_p)

    handles, last_cpu, stack_top = {}, {}, {}
    busy = []
    sim = None
    t0 = time.time()
    next_refresh = next_sim_scan = 0
    next_dump = t0 + window
    win_idx = 0
    flat, incl, samples, chains, cpu_window, joint, cond = (collections.Counter() for _ in range(7))
    win_start = None
    smbi = MEMORY_BASIC_INFORMATION()
    period = 1.0 / hz
    frame = STACKFRAME64()
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
            busy = [tid for d, tid in usage[:6] if d > 1_000_000]
            if sim is None and now >= next_sim_scan:
                next_sim_scan = now + 20.0
                sim = find_sim()
                if sim:
                    print("Sim object at 0x%X" % sim, flush=True)
            if win_start is None and sim:
                win_start = sim_state(sim)
            if k32.WaitForSingleObject(hp, 0) == 0:
                break
        round_chains = {}
        for tid in busy:
            h = handles.get(tid)
            if not h:
                continue
            if k32.SuspendThread(h) == 0xFFFFFFFF:
                continue
            try:
                struct.pack_into("<I", (ctypes.c_char * 0x4D0).from_address(CTX), OFF_FLAGS, CONTEXT_FULL)
                ok = k32.GetThreadContext(h, ctypes.c_void_p(CTX))
                data = None
                if ok:
                    rsp = ctypes.c_uint64.from_address(CTX + OFF_RSP).value
                    top = stack_top.get(tid)
                    if top is None or not (rsp < top <= rsp + 0x200000):
                        if k32.VirtualQueryEx(hp, ctypes.c_void_p(rsp), ctypes.byref(smbi), ctypes.sizeof(smbi)):
                            top = (smbi.BaseAddress or 0) + smbi.RegionSize
                            stack_top[tid] = top
                    if top:
                        data = rpm(hp, rsp, max(8, min(0x40000, top - rsp)))
            finally:
                k32.ResumeThread(h)
            if not ok:
                continue
            rip = ctypes.c_uint64.from_address(CTX + OFF_RIP).value
            snap["lo"] = rsp
            snap["data"] = data or b""
            ctypes.memset(ctypes.byref(frame), 0, ctypes.sizeof(frame))
            frame.AddrPC.Offset = rip
            frame.AddrPC.Mode = 3
            frame.AddrStack.Offset = rsp
            frame.AddrStack.Mode = 3
            frame.AddrFrame.Offset = ctypes.c_uint64.from_address(CTX + 0xA0).value
            frame.AddrFrame.Mode = 3
            chain = []
            pcs = 0
            while pcs < 160 and dbg.StackWalk64(0x8664, hp, h, ctypes.byref(frame), ctypes.c_void_p(CTX),
                                                read_mem, fta, gmb, None):
                pc = frame.AddrPC.Offset
                if not pc:
                    break
                f = func_of(pc if pcs == 0 else pc - 1)
                if not chain or chain[-1] != f:
                    chain.append(f)
                pcs += 1
            if not chain:
                chain = [func_of(rip)]
            samples[tid] += 1
            flat[(tid, chain[0])] += 1
            for f in set(chain):
                incl[(tid, f)] += 1
            chains[(tid, tuple(chain[:64]))] += 1
            round_chains[tid] = chain
        if len(round_chains) > 1:
            state = {t: (c[0] not in wait_ids) for t, c in round_chains.items()}
            joint[tuple(sorted(t for t, b in state.items() if b))] += 1
            for x, bx in state.items():
                for y, cy in round_chains.items():
                    if y != x:
                        for f in set(cy):
                            cond[(x, bx, y, f)] += 1
        elapsed = time.time() - now
        if elapsed < period:
            time.sleep(period - elapsed)
        if time.time() >= next_dump:
            state = sim_state(sim) if sim else None
            dump = {
                "window": win_idx, "window_s": window, "t": time.time() - t0, "sim_start": win_start, "sim_end": state,
                "cpu_100ns": {str(k): v for k, v in cpu_window.items()},
                "samples": {str(k): v for k, v in samples.items()},
                "names": names,
                "flat": [[t, k, v] for (t, k), v in flat.most_common(6000)],
                "incl": [[t, k, v] for (t, k), v in incl.most_common(12000)],
                "chains": [[t, list(c), v] for (t, c), v in chains.most_common(80000)],
                "joint": [[list(k), v] for k, v in joint.items()],
                "cond": [[x, bx, y, f, v] for (x, bx, y, f), v in cond.most_common(30000)],
            }
            with open(os.path.join(outdir, "win_%03d.json" % win_idx), "w") as fh:
                json.dump(dump, fh)
            print("window %d t=%.0fs samples=%s sim=%s" % (
                win_idx, dump["t"], dict(samples), {k: v for k, v in (state or {}).items() if k != "families"}
                | {"units": (state or {}).get("families", {}).get("unit")}), flush=True)
            win_idx += 1
            next_dump = time.time() + window
            for c in (flat, incl, samples, chains, cpu_window, joint, cond):
                c.clear()
            win_start = state
    winmm.timeEndPeriod(1)


if __name__ == "__main__":
    main()
