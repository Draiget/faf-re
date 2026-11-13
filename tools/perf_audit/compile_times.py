"""compile_times.py <log>... : per-effect compile times of a log (D3D11 'compiled effect ... in N ms', Vulkan/D3D12 'effect ...: (N ms)', cached-shader counts)."""
import re, sys

for path in sys.argv[1:]:
    t = open(path, errors='replace').read()
    out, tot = [], 0
    for m in re.finditer(r'compiled effect \S*effects[\\/](\w+)\.fx as fx_5_0 in (\d+) ms', t):
        out.append('%s %s' % (m.group(1), m.group(2)))
        tot += int(m.group(2))
    for m in re.finditer(r'(?:Vulkan|D3D12): effect \S*effects[\\/](\w+)\.fx: .*\((\d+) ms\)', t):
        out.append('%s %s' % (m.group(1), m.group(2)))
        tot += int(m.group(2))
    reads = re.findall(r'effects[\\/](\w+)\.fx: (\d+) of (\d+) shaders read from the cache ahead of use, (\d+) queued to compile', t)
    q = sum(int(r[3]) for r in reads)
    tot_sh = sum(int(r[2]) for r in reads)
    print('%s\n  effects: %s | total %d ms | shaders %d, queued to compile %d' % (path.split('/')[-1].split('\\')[-1], ', '.join(out), tot, tot_sh, q))
