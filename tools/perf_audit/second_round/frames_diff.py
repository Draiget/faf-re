"""frames_diff.py <labelA> <labelB> <cfgs> <scenes> <apis>: paused frames of two builds compared (last frames), and the frames of one run against each other"""
import glob, os, sys
import numpy as np
from PIL import Image
OUT = (os.environ.get('PERF_AUDIT_OUT', os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'out')).replace(chr(92), '/')) + '/perf_out'


def load(p):
    return np.asarray(Image.open(p).convert('RGB'), dtype=np.int16)


a_l, b_l = sys.argv[1], sys.argv[2]
for cfg in sys.argv[3].split(','):
    for scene in sys.argv[4].split(','):
        for api in sys.argv[5].split(','):
            a = sorted(glob.glob('%s/cmp_%s_%s_%s_%s/*.bmp' % (OUT, a_l, cfg, scene, api)))
            b = sorted(glob.glob('%s/cmp_%s_%s_%s_%s/*.bmp' % (OUT, b_l, cfg, scene, api)))
            if len(a) < 4 or len(b) < 4:
                print(cfg, scene, api, 'missing', len(a), len(b))
                continue
            fa = [load(a[i]) for i in (-3, -2, -1)]
            fb = [load(b[i]) for i in (-3, -2, -1)]
            noise = max(int(np.abs(fa[0] - fa[1]).max()), int(np.abs(fa[1] - fa[2]).max()), int(np.abs(fb[0] - fb[1]).max()), int(np.abs(fb[1] - fb[2]).max()))
            nz = max(float((np.abs(fa[1] - fa[2]).sum(axis=2) > 0).mean() * 100), float((np.abs(fb[1] - fb[2]).sum(axis=2) > 0).mean() * 100))
            res = []
            for i in range(3):
                d = np.abs(fa[i] - fb[i])
                res.append('max %d, %.3f %% px' % (int(d.max()), float((d.sum(axis=2) > 0).mean() * 100)))
            print('%-7s %-6s %-6s frames %d/%d  within one run: max %d, %.3f %% px | %s vs %s: %s' % (cfg, scene, api, len(a), len(b), noise, nz, a_l, b_l, ' ; '.join(res)))
            # mid-run frames too (the wide step: indices -9..-7)
            if len(a) >= 10 and len(b) >= 10:
                d = np.abs(load(a[-8]) - load(b[-8]))
                print('        wide step frame: max %d, %.3f %% px' % (int(d.max()), float((d.sum(axis=2) > 0).mean() * 100)))
