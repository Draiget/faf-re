# perf.py <log>: averages the per-pass GPU ms of the render profile blocks per ren_ShadowQuality mode (skips the first block after a switch)
import sys, re, collections
text = open(sys.argv[1], encoding='utf-8', errors='ignore').read().replace('\0', '')
mode = None; skip = 0
data = collections.defaultdict(lambda: collections.defaultdict(list))   # mode-key -> pass -> [gpu ms]
tot = collections.defaultdict(list)
seg = 0
for line in text.splitlines():
    m = re.search(r'SHADOW-TEST: mode (\d+) wall', line)
    if m:
        mode = (f'{m.group(1)}' if '--merge' in sys.argv else f'{m.group(1)}#{seg}'); seg += 1; skip = 2; continue
    if 'Render profile over' in line:
        if mode is None: continue
        if skip > 0: skip -= 1; cur = None; continue
        cur = mode
        g = re.search(r'GPU ([\d.]+) ms/frame', line); tot[cur].append(float(g.group(1)))
        continue
    m = re.match(r'info:\s+pass (\w+)\s+[\d.]+ calls\s+CPU\s+([\d.]+) ms\s+GPU\s+([\d.]+) ms', line)
    if m and mode is not None and skip == 0 and 'cur' in dir() and cur:
        data[cur][m.group(1)].append(float(m.group(3)))
names = ['Shadows', 'Terrain', 'TerrainContext', 'Meshes', 'MeshBatch', 'Reflections', 'Effects']
print('mode        n   GPUtotal  ' + '  '.join(f'{n:>10}' for n in names))
for k in tot:
    n = len(tot[k]); avg = lambda l: sum(l) / len(l) if l else 0
    print(f'{k:8} {n:4}  {avg(tot[k]):8.3f}  ' + '  '.join(f'{avg(data[k][nm]):10.3f}' for nm in names))
