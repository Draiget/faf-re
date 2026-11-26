import os
"""hitch_report.py <log> [thresholdMs=20] -> per step: window count, largest frame (max of the windows' max), windows with a frame over the threshold, and DynLights/Live switch lines"""
import sys, re, perf_parse as pp
log = sys.argv[1]; thr = float(sys.argv[2]) if len(sys.argv) > 2 else 20.0
steps, pre = pp.parse(log)
print('pre-step windows:', len(pre), 'max %.1f' % max([w.get('max', 0) for w in pre] or [0]))
tot = 0
for s in steps:
    ws = s['wins']
    if not ws: continue
    mx = max(w.get('max', 0) for w in ws)
    over = [w for w in ws if w.get('max', 0) > thr]
    tot += len(over)
    print('%-22s windows %3d  max frame %7.1f ms  windows over %.0f ms: %d  %s' % (s['label'], len(ws), mx, thr, len(over), ' '.join('%.0f' % w['max'] for w in over[:8])))
print('windows over threshold in all steps:', tot)
for l in open(log, errors='replace'):
    if re.search(r'Live switch|DynLights: .* textures read|Shadow filter: .*rebuilt|rebuilt in|compile took|compiled in', l):
        print(l.rstrip()[:200])
