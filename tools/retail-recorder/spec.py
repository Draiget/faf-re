"""Hook spec for the retail call recorder, generated from the IDA exports.

For every function in an inventory (one retail address per line, or the
coverage inventory TSV whose first column is the address) this reads
decomp/recovery/disasm/fa_full_2026_03_26/FUN_<addr>.asm and ida_c/FUN_<addr>.c
and decides:

- the prologue to copy into the trampoline: whole instructions, at least 5
  bytes, no relative branch, call or ret among them and no jump into them;
- how many argument bytes the function pops (its `ret N`);
- where each argument sits (register, from Hex-Rays' @<reg> or the calling
  convention, or a stack slot) and whether it is hashed: scalars are, pointers,
  references and structs passed by value are not (their raw value is an address
  or of unknown size, and addresses differ between processes);
- the result: eax (scalar), st0 (float or double), or none.

A function whose prototype disagrees with the asm (the stack bytes it implies
against `ret N`), or has an argument it cannot place, still gets hooked for its
call count, but none of its arguments are hashed, and it lands in the review
list. Hex-Rays types give the shape only (asm-pull notes), so the review list is
the part to read.

usage: spec.py <inventory> <out.bin> <report.txt>
"""
import json
import os
import re
import struct
import sys

EXPORTS = r"G:/projects/faf-main/decomp/recovery/disasm/fa_full_2026_03_26"
REG = {"eax": 0, "ecx": 1, "edx": 2, "ebx": 3, "esi": 4, "edi": 5, "ebp": 6}
STACK = 0x80
RET_NONE, RET_EAX, RET_ST0_FLOAT, RET_ST0_DOUBLE, RET_EDX_EAX, RET_AL, RET_AX, RET_XMM0_FLOAT, RET_EAX_POINTER = range(9)
REL_BRANCH = re.compile(r"^(E8|E9|EB|7[0-9A-F]|0F 8[0-9A-F]|E0|E1|E2|E3)\b")
SCALAR = re.compile(
    r"^(const\s+)?(unsigned\s+|signed\s+)?(int|char|short|long|bool|float|double|_BYTE|_WORD|_DWORD|_QWORD|"
    r"_BOOL1|_BOOL4|__int8|__int16|__int32|__int64|u?int(8|16|32|64)_t|size_t|BOOL|DWORD|WORD|BYTE)$"
)
ENUM = re.compile(r"^(const\s+)?(\w+::)*(E[A-Z]\w*|enum_\w+)$")


def read_asm(addr):
    path = f"{EXPORTS}/FUN_{addr:08X}.asm"
    if not os.path.exists(path):
        return None
    insns = []
    for line in open(path, encoding="utf-8", errors="replace"):
        m = re.match(r"^0x([0-9A-F]{8}):\s+((?:[0-9A-F]{2} )+)\s*(.*)$", line)
        if m:
            insns.append((int(m.group(1), 16), m.group(2).strip(), m.group(3).strip()))
    return insns


def prologue(addr, insns):
    targets = set()
    for _, _, text in insns:
        for t in re.finditer(r"0x([0-9a-f]+)", text):
            targets.add(int(t.group(1), 16))
    total = 0
    for _, hexbytes, text in insns:
        if REL_BRANCH.match(hexbytes) or text.startswith("ret"):
            return None, "relative branch, call or ret in the first 5 bytes"
        total += len(hexbytes.split())
        if total >= 5:
            break
    if total < 5:
        return None, "shorter than 5 bytes"
    if any(addr < t < addr + total for t in targets):
        return None, "jump into the copied bytes"
    return total, None


# Exports mix two spellings: capstone writes `ret 0x58`, IDA `retn 58h`
# (and plain `retn`). The h-suffix and the 0x-prefix must both parse, or
# every IDA-exported function reads as pop=0 and the recorder's unwind
# matching mis-attributes returns (the FUN_0069AFE0 eip=1 crash class).
# `retf` (far return) must not match: its trailing `f` is not an operand.
RET_INSN = re.compile(r"^ret[nw]?(?:\s+(.*))?$", re.IGNORECASE)


def pop_bytes(insns):
    pops = set()
    for _, _, text in insns:
        op_text = text.split(";", 1)[0].strip()  # drop `; 'X'`-style comments
        m = RET_INSN.match(op_text)
        if not m:
            continue
        op = (m.group(1) or "").strip()
        try:
            if not op:
                pops.add(0)
            elif op.lower().startswith("0x"):
                pops.add(int(op, 16))
            elif op.lower().endswith("h"):
                pops.add(int(op[:-1], 16))
            else:
                pops.add(int(op, 0))
        except ValueError:
            continue
    return pops


# Mnemonics that read a memory first operand. Every other instruction with a
# bracketed first operand counts as a store, so a mnemonic this list has never
# seen makes the function a writer, never a false "safe".
READS_FIRST_OPERAND = re.compile(
    r"^(cmp|test|push|call|jmp|j[a-z]+|bt|imul|mul|idiv|div|"
    r"fld|fild|fadd|faddp|fmul|fmulp|fsub|fsubp|fsubr|fsubrp|fdiv|fdivp|fdivr|fdivrp|"
    r"fiadd|fimul|fisub|fisubr|fidiv|fidivr|fcom|fcomp|ficom|ficomp|fldcw|fldenv|"
    r"comiss|comisd|ucomiss|ucomisd|prefetch\w*)$"
)
# Plain own-frame addressing: no index register, so an edge value used as an
# array index cannot walk it out of the frame.
ESP_SLOT = re.compile(r"^\[esp(\s*[-+]\s*(0x[0-9a-fA-F]+|[0-9A-Fa-f]+h?))?\]$")
EBP_SLOT = re.compile(r"^\[ebp(\s*[-+]\s*(0x[0-9a-fA-F]+|[0-9A-Fa-f]+h?))?\]$")
SIZE_PREFIX = re.compile(r"^(?:(?:byte|word|dword|qword|tbyte|xmmword|oword|xword)\s+ptr\s+)?(.*)$")
SWITCH_JUMP = re.compile(r"^dword ptr \[\w+\*4\s*\+\s*0x[0-9a-fA-F]+\]$")
FLOW_LITERAL = re.compile(r"^(?:short\s+)?0x([0-9a-fA-F]+)$")
FLOW_NAME = re.compile(r"^(?:short\s+|near ptr\s+)?(?:sub|loc|locret|FUN|j)_([0-9A-Fa-f]+)$")


def first_operand(operands):
    depth, first = 0, ""
    for ch in operands:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            break
        first += ch
    return first.strip()


def flow_of(insns):
    """What the function can reach and whether it can store outside its frame.

    Returns (stores, edges): `stores` is True for a store that is not plainly
    into the function's own frame, for a jump or call whose target the asm does
    not name, and for an export that does not end in a return or a jump (it may
    be truncated, and what it does not show cannot be called safe). `edges` is
    every address a call or a jump leaves the function for.

    The probe (re-calling a function with edge arguments inside the live game)
    is only safe without side effects: a store through an argument pointer or
    to a global would change the game and break the replay, and a result
    written through a pointer overwrites what the real caller is about to read.
    """
    if not insns:
        return True, set()
    start, end = insns[0][0], insns[-1][0]
    last = insns[-1][2].split(";")[0].split()
    if not last or not (last[0].startswith("ret") or last[0] == "jmp" or last[0] == "int3"):
        return True, set()
    framed = any(i[2].split(";")[0].split() == ["mov", "ebp,", "esp"] for i in insns[:4])
    stores, edges = False, set()
    for _, _, raw in insns:
        text = raw.split(";")[0].strip()
        parts = text.split(None, 1)
        if not parts:
            continue
        mnemonic = parts[0]
        operands = parts[1].strip() if len(parts) > 1 else ""
        if mnemonic in ("lock", "rep", "repe", "repz", "repne", "repnz"):
            inner = operands.split()[0] if operands else ""
            if not re.match(r"^(cmps|scas|lods)", inner):
                stores = True
            continue
        if mnemonic.startswith(("stos", "ins", "outs")) or mnemonic in ("movsb", "movsw"):
            stores = True
            continue
        if mnemonic in ("xchg", "cmpxchg", "xadd") and "[" in operands:
            stores = True
            continue
        if mnemonic == "call" or mnemonic.startswith("j"):
            target = None
            annotated = CALL_TARGET.search(raw)
            literal = FLOW_LITERAL.match(operands) or FLOW_NAME.match(operands)
            if annotated:
                target = int(annotated.group(1)[4:], 16)
            elif literal:
                target = int(literal.group(1), 16)
            if target is None:
                # A compiler jump table stays in the function; any other
                # register or memory target is a virtual call or an import.
                if not (mnemonic == "jmp" and SWITCH_JUMP.match(operands)):
                    stores = True
                continue
            if mnemonic == "call" or not start <= target <= end:
                edges.add(target)
            continue
        first = first_operand(operands)
        if "[" not in first or READS_FIRST_OPERAND.match(mnemonic):
            continue
        dest = SIZE_PREFIX.match(first).group(1).strip()
        if ESP_SLOT.match(dest) or (framed and EBP_SLOT.match(dest)):
            continue
        stores = True
    return stores, edges


# A call target the asm annotates (`call 0x... ; -> FUN_x`).
CALL_TARGET = re.compile(r"-> (FUN_[0-9A-F]{8})")


def prototype(addr):
    path = f"{EXPORTS}/ida_c/FUN_{addr:08X}.c"
    if not os.path.exists(path):
        return None
    text = ""
    depth = 0
    started = False
    for line in open(path, encoding="utf-8", errors="replace"):
        if not started:
            if line.startswith("//") or "(" not in line:
                continue
            started = True
        text += " " + line.strip()
        depth += line.count("(") - line.count(")")
        if started and depth <= 0:
            break
    return text.strip()


def split_params(inner):
    parts, depth, cur = [], 0, ""
    for ch in inner:
        if ch in "(<":
            depth += 1
        elif ch in ")>":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur.strip())
    return parts


def classify(ptype):
    t = ptype.strip()
    if t.endswith("*") or t.endswith("&") or "*" in t or "&" in t:
        return "pointer", 4
    if SCALAR.match(t) or ENUM.match(t):
        return "scalar", 8 if re.search(r"double|__int64|_QWORD|int64_t", t) else 4
    return "struct", None


def is_float(ptype):
    return re.match(r"^(const\s+)?(float|double)$", ptype.strip()) is not None


def parse(proto):
    m = re.match(r"^(.*?)\(\s*(.*)\)\s*$", proto)
    if not m:
        return None
    head, inner = m.group(1).strip(), m.group(2).strip()
    cc = "cdecl"
    for c in ("cdecl", "stdcall", "thiscall", "fastcall", "usercall", "userpurge"):
        if f"__{c}" in head:
            cc = c
    head = re.sub(r"__(cdecl|stdcall|thiscall|fastcall|usercall|userpurge|noreturn|spoils<[^>]*>)", "", head)
    retloc = None
    rm = re.search(r"@<(\w+)>\s*$", head)
    if rm:
        retloc = rm.group(1)
        head = head[: rm.start()].strip()
    name_m = re.search(r"([\w:~<>]+)\s*$", head)
    rettype = head[: name_m.start()].strip() if name_m else head
    params = []
    if inner and inner != "void":
        for p in split_params(inner):
            if p == "...":
                params.append(("...", None, None))
                continue
            loc = None
            lm = re.search(r"@<(\w+)>\s*$", p)
            if lm:
                loc = lm.group(1)
                p = p[: lm.start()].strip()
            pm = re.match(r"^(.*?)([\w]+)\s*$", p)
            ptype = pm.group(1).strip() if pm and pm.group(1).strip() else p
            params.append((ptype, loc, p))
    return cc, rettype, retloc, params


def entered_by_jump(addr):
    # A block some code reaches with a jmp (a shared tail, or a tail call) does
    # not start with a return address on the stack: swapping [esp] there broke
    # a saved value, and the game returned to address 5.
    path = f"{EXPORTS}/FUN_{addr:08X}.meta.json"
    if not os.path.exists(path):
        return False
    meta = json.load(open(path, encoding="utf-8"))
    for x in meta.get("incoming_xrefs", []):
        if x.get("kind") != "code" or x.get("to_ea") != addr:
            continue
        line = (x.get("line") or "").strip()
        if x.get("type") == 19 or (line.startswith("j") and not line.startswith("jmp     ds:")):
            return True
    return False


def spec_for(addr):
    insns = read_asm(addr)
    if not insns:
        return None, "no export"
    if insns[0][0] != addr:
        return None, "export starts elsewhere"
    if entered_by_jump(addr):
        return None, "entered by a jump from other code"
    plen, why = prologue(addr, insns)
    if plen is None:
        return None, why
    pops = pop_bytes(insns)
    # Disagreeing `ret N` sizes cannot be resolved statically: MSVC8 SEH
    # functions end their exception-dispatch path in a plain `ret` (the
    # `mov eax, <continue target>; ret` at FUN_0069F6A3) while every normal
    # exit uses `ret N`, and the recorder's unwind matching needs the one
    # pop the taken path will use. Hooking such a function leaves the stub's
    # stack math wrong on the SEH path (a longjmp/unwind then returns to
    # garbage and kills the game), so it is left unhooked.
    if len(pops) > 1:
        return None, f"several ret sizes {sorted(pops)} (an SEH continue path)"
    pop = max(pops) if pops else 0
    entry = {"va": addr, "prologue": plen, "pop": pop, "args": [], "ret": RET_NONE, "review": None, "writes": 1}
    proto = prototype(addr)
    parsed = parse(proto) if proto else None
    if parsed is None:
        entry["review"] = "no prototype"
        return entry, None
    cc, rettype, retloc, params = parsed
    args, stack_off, fast_regs = [], 0, ["ecx", "edx"]
    for i, (ptype, loc, raw) in enumerate(params):
        if ptype == "...":
            break
        kind, size = classify(ptype)
        if loc is None:
            if cc == "thiscall" and i == 0:
                loc = "ecx"
            elif cc == "fastcall" and fast_regs and size == 4:
                loc = fast_regs.pop(0)
        if loc is not None:
            if loc not in REG:
                entry["review"] = entry["review"] or f"argument in {loc}"
                continue
            args.append((REG[loc], 1, kind == "scalar", is_float(ptype)))
            continue
        if size is None:
            entry["review"] = entry["review"] or f"struct by value: {raw}"
            size = 4  # unknown: placement of later arguments is unreliable
        words = size // 4
        args.append((STACK | (stack_off // 4), words, kind == "scalar", is_float(ptype)))
        stack_off += size
    implied_pop = stack_off if cc in ("stdcall", "thiscall", "fastcall", "userpurge") else 0
    if implied_pop != pop and entry["review"] is None:
        entry["review"] = f"prototype implies ret {implied_pop}, asm has ret {pop}"
    rt = rettype.strip()
    if retloc == "al":
        entry["ret"] = RET_AL
    elif retloc == "ax":
        entry["ret"] = RET_AX
    elif retloc == "xmm0":
        entry["ret"] = RET_XMM0_FLOAT
    elif retloc in ("st0",) or (retloc is None and re.match(r"^(const\s+)?float$", rt)):
        entry["ret"] = RET_ST0_FLOAT
    elif retloc is None and re.match(r"^(const\s+)?(long\s+)?double$", rt):
        entry["ret"] = RET_ST0_DOUBLE
    elif rt.startswith("void") and "*" not in rt:
        entry["ret"] = RET_NONE
    elif retloc in (None, "eax") and classify(rt)[0] == "pointer":
        entry["ret"] = RET_EAX_POINTER
    elif retloc is None and re.match(r"^(const\s+)?(unsigned\s+|signed\s+)?(char|bool|_BYTE|_BOOL1|__int8)$", rt):
        entry["ret"] = RET_AL  # the upper bytes of eax are whatever was there
    elif retloc is None and re.match(r"^(const\s+)?(unsigned\s+|signed\s+)?(short|_WORD|__int16)$", rt):
        entry["ret"] = RET_AX
    elif retloc in (None, "eax") and classify(rt)[0] == "scalar":
        entry["ret"] = RET_EDX_EAX if classify(rt)[1] == 8 else RET_EAX
    if entry["review"] is None:
        entry["args"] = args
    else:
        entry["ret"] = (
            entry["ret"]
            if entry["ret"] in (RET_ST0_FLOAT, RET_ST0_DOUBLE, RET_EAX, RET_AL, RET_AX, RET_XMM0_FLOAT)
            else RET_NONE
        )
    return entry, None


def transitive_writes(specs):
    """Sets each entry's `writes`: a function is probe-safe only when nothing it
    can reach, through calls and through jumps out of it, stores outside its own
    stack frame. The walk follows every export, hooked or not. An address with
    no export (an import, code outside the exports) is a writer: unknown, not
    safe. A cycle is fine: writers propagate along the edges until nothing
    changes, so a cycle member is a writer exactly when a writer is reachable.
    """
    stores, edges = {}, {}
    pending = [e["va"] for e in specs]
    while pending:
        va = pending.pop()
        if va in stores:
            continue
        stores[va], edges[va] = flow_of(read_asm(va))
        pending.extend(t for t in edges[va] if t not in stores)
    callers = {}
    for va, targets in edges.items():
        for t in targets:
            callers.setdefault(t, []).append(va)
    writers = [va for va, wrote in stores.items() if wrote]
    seen = set(writers)
    while writers:
        for caller in callers.get(writers.pop(), ()):
            if caller not in seen:
                seen.add(caller)
                writers.append(caller)
    for e in specs:
        e["writes"] = 1 if e["va"] in seen else 0


def main():
    inventory, out_bin, report = sys.argv[1], sys.argv[2], sys.argv[3]
    addrs = []
    for line in open(inventory, encoding="utf-8"):
        first = line.split("\t")[0].strip()
        if re.match(r"^0x[0-9A-Fa-f]{8}$", first):
            addrs.append(int(first, 16))
    addrs = sorted(set(addrs))
    specs, skipped, review = [], {}, []
    for a in addrs:
        entry, why = spec_for(a)
        if entry is None:
            skipped[why] = skipped.get(why, 0) + 1
            continue
        specs.append(entry)
        if entry["review"]:
            review.append((a, entry["review"]))
    transitive_writes(specs)
    with open(out_bin, "wb") as f:
        f.write(b"RRS2" + struct.pack("<I", len(specs)))
        for e in specs:
            # va, pop bytes, prologue bytes, result kind, argument count (9 bytes)
            f.write(struct.pack("<IHBBB", e["va"], e["pop"], e["prologue"], e["ret"], len(e["args"])))
            # writes: 1 = the function stores outside its result and frame
            # (its extra probe calls would change the game), 0 = probe-safe
            f.write(struct.pack("<B", e["writes"]))
            # location (register index, or 0x80 | stack dword), words, hashed, float
            for loc, words, hashed, flt in e["args"]:
                f.write(struct.pack("<BBBB", loc, words, 1 if hashed else 0, 1 if flt else 0))
    hashed_args = sum(1 for e in specs for a in e["args"] if a[2])
    probe_safe = sum(1 for e in specs if not e["writes"])
    with open(report, "w", encoding="utf-8") as f:
        f.write(f"inventory addresses: {len(addrs)}\nhooked: {len(specs)}\n")
        f.write(f"hooked with arguments placed and checked: {len(specs) - len(review)}\n")
        f.write(f"hooked for the call count only (review list): {len(review)}\n")
        f.write(f"hashed scalar arguments: {hashed_args}\n")
        f.write(f"results hashed: {sum(1 for e in specs if e['ret'] not in (RET_NONE, RET_EAX_POINTER))}\n")
        f.write(f"probe-safe (writes nothing outside result and frame): {probe_safe}\n")
        for why, n in sorted(skipped.items(), key=lambda kv: -kv[1]):
            f.write(f"not hooked: {n:5d}  {why}\n")
        f.write("\nreview list:\n")
        for a, why in review:
            f.write(f"0x{a:08X}  {why}\n")
    print(open(report, encoding="utf-8").read().split("\nreview list:")[0])


if __name__ == "__main__":
    main()
