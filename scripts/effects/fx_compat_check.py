"""Compile every effect the way each engine backend does and list what breaks.

`CD3DEffect::InitEffectFromFile` puts `/effects/d3d9states.compat` or
`/effects/d3d10states.compat` in front of each .fx before compiling it, and
`DeviceD3D10::CreateEffect` also defines the 20 macros in
`kDeviceCreateEffectInjectedMacros`. This does the same with the SDK's fxc:

    D3D9   fx_2_0              (control; the game itself uses the lenient
                                legacy d3dx9_31 compiler, so a failure here
                                can be a strictness difference)
    D3D10  fx_4_0 /Gec         (/Gec = HLSL flag 0x1000, backwards
                                compatibility, as the backend passes)

fxc stops at the first effect-state error, so for D3D10 the preprocessed
source is also scanned: inside a pass, fx_4_0 accepts only Set*Shader and
Set*State calls, so every other `Name = value;` is raw D3D9 pass state that
has to move into a compat macro or a state object. Those passes are listed
per technique - that list is the work.

Usage:
    python scripts/effects/fx_compat_check.py [--effects DIR] [--only NAME ...]
"""
import argparse
import collections
import os
import re
import subprocess
import sys
import tempfile

DEFAULT_EFFECTS = os.path.join(os.path.dirname(__file__), "..", "..", "gamedata", "effects")
DEFAULT_FXC = r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000.0\x86\fxc.exe"

# DeviceD3D10::CreateEffect defines these on top of the compat prelude.
D3D10_MACROS = [
    ("technique", "technique10"), ("VERSION", "DIRECT3D10"),
    ("vs_1_1", "vs_4_0"), ("vs_1_3", "vs_4_0"), ("vs_1_4", "vs_4_0"), ("vs_2_0", "vs_4_0"), ("vs_3_0", "vs_4_0"),
    ("ps_1_1", "ps_4_0"), ("ps_1_3", "ps_4_0"), ("ps_1_4", "ps_4_0"), ("ps_2_0", "ps_4_0"), ("ps_2_a", "ps_4_0"),
    ("ps_2_b", "ps_4_0"), ("ps_3_0", "ps_4_0"),
    ("MipFilter", "Filter"), ("MinFilter", "Filter"), ("MagFilter", "Filter"),
    ("NONE", "MIN_MAG_MIP_POINT"), ("LINEAR", "MIN_MAG_MIP_LINEAR"), ("POINT", "MIN_MAG_MIP_POINT"),
]
SHADER_ASSIGNMENTS = {"VertexShader", "PixelShader", "GeometryShader"}
LEGAL_PASS_CALL = re.compile(r"^\s*Set(Vertex|Pixel|Geometry)Shader\b|^\s*Set(Blend|DepthStencil|Rasterizer)State\b")


def run_fxc(fxc, arguments, workdir):
    """Runs fxc without a shell (no MSYS path mangling) and returns (exit, stderr)."""
    result = subprocess.run([fxc, "/nologo"] + arguments, cwd=workdir, capture_output=True, text=True, errors="replace")
    noise = "warning X4717"  # effects deprecated in d3dcompiler_47: expected on every file
    lines = [line for line in (result.stderr + result.stdout).splitlines() if line.strip() and noise not in line]
    return result.returncode, lines


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def drifted_passes(preprocessed):
    """(technique, pass, [assigned names]) for every pass with raw D3D9 state."""
    text = strip_comments(preprocessed)
    results = []
    for technique in re.finditer(r"\btechnique1[01]\s+(\w+)[^{]*\{", text):
        depth, index = 1, technique.end()
        while depth and index < len(text):
            depth += {"{": 1, "}": -1}.get(text[index], 0)
            index += 1
        body = text[technique.end():index - 1]
        for pass_match in re.finditer(r"\bpass\s*(\w*)[^{]*\{", body):
            pdepth, pindex = 1, pass_match.end()
            while pdepth and pindex < len(body):
                pdepth += {"{": 1, "}": -1}.get(body[pindex], 0)
                pindex += 1
            statements = [s for s in body[pass_match.end():pindex - 1].split(";") if s.strip()]
            names = []
            for statement in statements:
                if LEGAL_PASS_CALL.match(statement):
                    continue
                assignment = re.match(r"\s*(\w+)\s*(\[[^\]]*\])?\s*=", statement)
                # fx_4_0 under /Gec still takes the D3D9 shader assignments.
                if assignment and assignment.group(1) not in SHADER_ASSIGNMENTS:
                    names.append(assignment.group(1))
            if names:
                results.append((technique.group(1), pass_match.group(1) or "?", names))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--effects", default=DEFAULT_EFFECTS, help="directory holding the .fx and .compat files")
    parser.add_argument("--fxc", default=DEFAULT_FXC)
    parser.add_argument("--only", nargs="*", help="effect names to check (default: all)")
    parser.add_argument("--list", action="store_true", help="print every drifted pass, not just counts")
    args = parser.parse_args()

    effects = os.path.abspath(args.effects)
    compat = {api: open(os.path.join(effects, f"{api}states.compat"), encoding="latin1").read() for api in ("d3d9", "d3d10")}
    names = sorted(n[:-3] for n in os.listdir(effects) if n.endswith(".fx"))
    if args.only:
        names = [n for n in names if n in args.only]

    summary = []
    with tempfile.TemporaryDirectory() as work:
        for name in names:
            source = open(os.path.join(effects, name + ".fx"), encoding="latin1").read()
            row = {"name": name}
            for api, target, extra in (("d3d9", "fx_2_0", []), ("d3d10", "fx_4_0", ["/Gec"])):
                merged = os.path.join(work, f"{name}.{api}.fx")
                with open(merged, "w", encoding="latin1") as handle:
                    handle.write(compat[api] + "\n" + source)
                defines = [f"/D{key}={value}" for key, value in D3D10_MACROS] if api == "d3d10" else []
                code, messages = run_fxc(args.fxc, ["/T", target] + extra + defines + ["/Fo", f"{name}.{api}.fxo", merged], work)
                row[api] = (code, messages)
                if api == "d3d10":
                    # fxc refuses /P together with /T ("cannot preprocess to file
                    # and compile at the same time").
                    run_fxc(args.fxc, defines + ["/P", f"{name}.pp", merged], work)
                    preprocessed_path = os.path.join(work, f"{name}.pp")
                    passes = drifted_passes(open(preprocessed_path, encoding="latin1").read()) if os.path.exists(preprocessed_path) else []
                    row["drift"] = passes
            summary.append(row)

    total_drift = 0
    for row in summary:
        d9, d10 = row["d3d9"], row["d3d10"]
        drift = row["drift"]
        total_drift += len(drift)
        first_error = next((m for m in d10[1] if "error" in m.lower()), "")
        print(f"{row['name']:14s} d3d9={'ok ' if d9[0] == 0 else 'ERR'} d3d10={'ok ' if d10[0] == 0 else 'ERR'} "
              f"drifted passes={len(drift):3d}  {first_error.split(': error ')[-1][:90] if first_error else ''}")
        if args.list:
            by_name = collections.Counter(n for _, _, names in drift for n in names)
            for technique, pass_name, assigned in drift:
                print(f"    {technique}::{pass_name}: {', '.join(assigned)}")
            if by_name:
                print(f"    states: {dict(by_name.most_common())}")
    compiled = sum(1 for row in summary if row["d3d10"][0] == 0)
    print(f"\nD3D10: {compiled}/{len(summary)} effects compile; {total_drift} passes carry raw D3D9 state")
    return 0 if compiled == len(summary) and total_drift == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
