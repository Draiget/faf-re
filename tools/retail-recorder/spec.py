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
RET_NONE, RET_EAX, RET_ST0_FLOAT, RET_ST0_DOUBLE, RET_EDX_EAX = 0, 1, 2, 3, 4
REL_BRANCH = re.compile(r"^(E8|E9|EB|7[0-9A-F]|0F 8[0-9A-F]|E0|E1|E2|E3)\b")
SCALAR = re.compile(
    r"^(const\s+)?(unsigned\s+|signed\s+)?(int|char|short|long|bool|float|double|_BYTE|_WORD|_DWORD|_QWORD|"
    r"_BOOL1|_BOOL4|__int8|__int16|__int32|__int64|u?int(8|16|32|64)_t|size_t|BOOL|DWORD|WORD|BYTE)$"
)
ENUM = re.compile(r"^(const\s+)?(\w+::)*E[A-Z]\w*$")


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


def pop_bytes(insns):
    pops = set()
    for _, _, text in insns:
        m = re.match(r"^ret\s*(0x[0-9a-f]+|\d+)?$", text)
        if m:
            pops.add(int(m.group(1), 0) if m.group(1) else 0)
    return pops


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
    pop = max(pops) if pops else 0
    entry = {"va": addr, "prologue": plen, "pop": pop, "args": [], "ret": RET_NONE, "review": None}
    proto = prototype(addr)
    parsed = parse(proto) if proto else None
    if parsed is None:
        entry["review"] = "no prototype"
        return entry, None
    cc, rettype, retloc, params = parsed
    if len(pops) > 1:
        entry["review"] = f"several ret sizes {sorted(pops)}"
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
    if retloc in ("st0",) or (retloc is None and re.match(r"^(const\s+)?float$", rt)):
        entry["ret"] = RET_ST0_FLOAT
    elif retloc is None and re.match(r"^(const\s+)?double$", rt):
        entry["ret"] = RET_ST0_DOUBLE
    elif rt.startswith("void") and "*" not in rt:
        entry["ret"] = RET_NONE
    elif retloc in (None, "eax") and classify(rt)[0] == "scalar":
        entry["ret"] = RET_EDX_EAX if classify(rt)[1] == 8 else RET_EAX
    if entry["review"] is None:
        entry["args"] = args
    else:
        entry["ret"] = entry["ret"] if entry["ret"] in (RET_ST0_FLOAT, RET_ST0_DOUBLE, RET_EAX) else RET_NONE
    return entry, None


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
    with open(out_bin, "wb") as f:
        f.write(b"RRS1" + struct.pack("<I", len(specs)))
        for e in specs:
            # va, pop bytes, prologue bytes, result kind, argument count (9 bytes)
            f.write(struct.pack("<IHBBB", e["va"], e["pop"], e["prologue"], e["ret"], len(e["args"])))
            # location (register index, or 0x80 | stack dword), words, hashed, float
            for loc, words, hashed, flt in e["args"]:
                f.write(struct.pack("<BBBB", loc, words, 1 if hashed else 0, 1 if flt else 0))
    hashed_args = sum(1 for e in specs for a in e["args"] if a[2])
    with open(report, "w", encoding="utf-8") as f:
        f.write(f"inventory addresses: {len(addrs)}\nhooked: {len(specs)}\n")
        f.write(f"hooked with arguments placed and checked: {len(specs) - len(review)}\n")
        f.write(f"hooked for the call count only (review list): {len(review)}\n")
        f.write(f"hashed scalar arguments: {hashed_args}\n")
        f.write(f"results hashed: {sum(1 for e in specs if e['ret'] != RET_NONE)}\n")
        for why, n in sorted(skipped.items(), key=lambda kv: -kv[1]):
            f.write(f"not hooked: {n:5d}  {why}\n")
        f.write("\nreview list:\n")
        for a, why in review:
            f.write(f"0x{a:08X}  {why}\n")
    print(open(report, encoding="utf-8").read().split("\nreview list:")[0])


if __name__ == "__main__":
    main()
