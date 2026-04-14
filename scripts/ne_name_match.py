#!/usr/bin/env python3
"""For each needs_evidence token with an engine/MOHO symbol name, try to
find the function already defined in src/sdk (maybe missing address
annotation). If found, emit the token for re-promotion.
"""
from __future__ import annotations
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DISASM = ROOT / "decomp" / "recovery" / "disasm" / "fa_full_2026_03_26"
SRC = ROOT / "src" / "sdk"

NAME_RE = re.compile(r"^# Function (.+)$", re.MULTILINE)


def extract_short_name(name: str) -> str | None:
    """From a raw IDA name, extract a searchable C++ identifier.
    Examples:
      Moho::MultQuadVec -> MultQuadVec
      ??1RenderTargetContext@gal@gpg@@QAE@@Z [gpg::gal::RenderTargetContext::~RenderTargetContext] -> ~RenderTargetContext
      sub_XXXXXX -> None
    """
    n = name.strip()
    if re.match(r"^sub_[0-9A-Fa-f]+$", n):
        return None
    # Look for `[xxx::yyy::name]` style
    m = re.search(r"\[([^\]]+)\]", n)
    if m:
        n = m.group(1)
    # Strip parameter list
    n = n.split("(", 1)[0]
    # Take last component after ::
    parts = n.split("::")
    last = parts[-1].strip()
    if not last:
        return None
    # Strip trailing angle brackets for templates
    last = re.sub(r"<.*", "", last)
    # Dtor form ~Name
    if last.startswith("~"):
        return last
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", last):
        return None
    return last


def main():
    import json
    ext = json.load(open(ROOT / "scripts" / "ne_external_scan.json"))
    candidates = ext.get("(engine)", [])

    # Build src index once using grep across src/sdk
    print(f"searching {len(candidates)} tokens against src/sdk")

    with open(ROOT / "decomp" / "recovery" / "recovered_progress.json", encoding="utf-8") as f:
        data = json.load(f)
    rec = data["namespaces"]["fa_full_2026_03_26"]["recovered"]

    matches = []
    for tok in candidates:
        md = DISASM / f"{tok}.md"
        if not md.exists():
            continue
        txt = md.read_text(encoding="utf-8", errors="replace")
        m = NAME_RE.search(txt)
        if not m:
            continue
        raw = m.group(1).strip()
        short = extract_short_name(raw)
        if not short:
            continue
        # Search src/sdk for function definition with this name
        # Very rough: look for `short\s*\(` in .cpp/.h
        try:
            result = subprocess.run(
                [
                    "rg", "--no-config", "-l", "-g", "*.cpp", "-g", "*.h",
                    rf"\b{re.escape(short)}\s*\(",
                    str(SRC),
                ],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0 and result.stdout.strip():
                files = result.stdout.strip().splitlines()
                matches.append((tok, raw, short, files))
        except Exception:
            pass

    print(f"matched {len(matches)} tokens to src/sdk")
    out = ROOT / "scripts" / "ne_name_matches.json"
    out.write_text(json.dumps([
        {"token": t, "name": n, "short": s, "files": f}
        for t, n, s, f in matches
    ], indent=2), encoding="utf-8")
    for t, n, s, f in matches[:15]:
        print(f"  {t} -> {s} in {len(f)} files")


if __name__ == "__main__":
    main()
