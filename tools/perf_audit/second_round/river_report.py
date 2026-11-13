import os, sys, statistics as S
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))   # tools/perf_audit
import perf_parse as pp
log = sys.argv[1]
st = pp.parse(log)[0]
print('%-18s %6s %6s %6s | Water cpu/gpu/draws | WaterFeed WaterStep Waterfalls Frame-cpu' % ('step', 'gpu', 'cpu', 'draws'))
for s in st:
    r = pp.step_stats(s)
    if not r:
        continue
    wins = s['wins'][len(s['wins']) // 2:]

    def pv(n, i):
        v = [w['passes'][n][i] for w in wins if n in w['passes']]
        return S.median(v) if v else float('nan')
    print('%-18s %6.2f %6.2f %6.1f | %5.3f/%5.3f/%5.1f | %5.3f %5.3f %5.3f' % (s['label'], r['gpu'], r['cpu'], r['draws'], pv('Water', 0), pv('Water', 1), pv('Water', 2), pv('WaterFeed', 0), pv('WaterStep', 0), pv('Waterfalls', 0)))
