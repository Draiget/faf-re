#!/usr/bin/env python3
"""Scan remaining needs_evidence for external-library symbols.

Looks at each token's md for known external symbol name prefixes
(ADX/CRI, lua_, png_, z_, bugsplat_, wxWidget...) and classifies them as
external_dependency.
"""
from __future__ import annotations
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROG = ROOT / "decomp" / "recovery" / "recovered_progress.json"
DISASM = ROOT / "decomp" / "recovery" / "disasm" / "fa_full_2026_03_26"

NAME_RE = re.compile(r"^# Function (.+)$", re.MULTILINE)

EXTERNAL_PATTERNS = {
    "adx_cri": re.compile(r"^(_?ADX|_?CRI|_?adx|_?cri|_?sj|_?HCA)", re.I),
    "lua": re.compile(r"^(lua[A-Z_]|luaL_|luaI_|luaM_|luaS_|luaT_|luaV_|luaG_|luaD_|luaO_|luaF_|luaH_|luaX_|luaY_|luaZ_|luaK_|luaP_|luaU_|luaC_|luaB_|luaopen_|l_|auxreset|readline)"),
    "png": re.compile(r"^png_"),
    "zlib": re.compile(r"^(deflate|inflate|adler32|crc32|zcalloc|zcfree|_tr_|zlib|gz)"),
    "bugsplat": re.compile(r"^(BugSplat|bugsplat|bs_|CrashRpt|MiniDump)", re.I),
    "wxwidgets": re.compile(r"^(wx[A-Z]|_wx)"),
    "msvc_crt": re.compile(r"^(_?(crt|CRT|__security_|__report_|__cxa_|_setmode|_fsopen|_ftbuf|_filbuf|_flsbuf|_open|_close|_read|_write|_lseek|_stat|_fstat|_getbuf|_stbuf|_strerror|_strdup|_wcsdup|_malloc|_calloc|_realloc|_free|_mbctype|_heap|__allocmap|_ioinit|_cinit|_C_term|_exit|_onexit|_initterm|_controlfp|_except_handler|_fptrap|__dllonexit|_amsg_exit|_getmainargs|_getcmdline|_acmdln|_wcmdln|__set_app_type|___lc_))|^(sqrtf?|sinf?|cosf?|tanf?|asinf?|acosf?|atan2?f?|expf?|logf?|log10f?|powf?|floorf?|ceilf?|fabsf?|fmodf?|ldexpf?|frexpf?|modff?|roundf?|truncf?|rintf?|hypotf?|strcpy|strncpy|strcat|strncat|strlen|strcmp|strncmp|strchr|strrchr|strstr|strtok|memcpy|memmove|memset|memcmp|memchr|printf|sprintf|snprintf|fprintf|vprintf|vsprintf|atoi|atol|atof|strtol|strtoul|strtod|qsort|bsearch|rand|srand|time|clock|abort|exit|atexit|assert|setjmp|longjmp)$"),
    "boost": re.compile(r"^boost(::|_)|^::boost(::|_)"),
    "msvc_stl": re.compile(r"^(std::|::std::|_Tree|_Dinkum|_Debug_message|_Xlen|_Xran|_Xout|_Xbad)"),
    "undname": re.compile(r"^(undname|__unDName|_?get_dp|dname_)", re.I),
    "sofdec": re.compile(r"^(Sofdec|SFD|sfd_|sofdec_)", re.I),
}


def classify_external(name: str) -> str | None:
    name = name.strip()
    for kind, pat in EXTERNAL_PATTERNS.items():
        if pat.search(name):
            return kind
    return None


def main():
    with open(PROG, encoding="utf-8") as f:
        data = json.load(f)
    rec = data["namespaces"]["fa_full_2026_03_26"]["recovered"]
    ne_toks = [
        t for t, v in rec.items()
        if isinstance(v, dict) and v.get("status") == "needs_evidence"
    ]

    by_kind = defaultdict(list)
    unmatched = 0
    for tok in ne_toks:
        md = DISASM / f"{tok}.md"
        if not md.exists():
            unmatched += 1
            continue
        try:
            txt = md.read_text(encoding="utf-8", errors="replace")
        except OSError:
            unmatched += 1
            continue
        m = NAME_RE.search(txt)
        if not m:
            unmatched += 1
            continue
        name = m.group(1).strip()
        kind = classify_external(name)
        if kind:
            by_kind[kind].append((tok, name))
        else:
            # Not external — check if name is "sub_XXXXXX" (generic) or real
            if re.match(r"^sub_[0-9A-Fa-f]+$", name):
                by_kind["(generic-sub)"].append((tok, name))
            else:
                by_kind["(engine)"].append((tok, name))

    for k, v in sorted(by_kind.items(), key=lambda x: -len(x[1])):
        print(f"{k}: {len(v)}")
        for tok, name in v[:3]:
            print(f"    {tok}  {name}")

    out = {k: [tok for tok, _ in v] for k, v in by_kind.items()}
    out_path = ROOT / "scripts" / "ne_external_scan.json"
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
