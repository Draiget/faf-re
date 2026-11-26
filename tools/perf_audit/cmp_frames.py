import os
"""cmp_frames.py -> for each scene and API: the paused frames of the two builds (cmp_old_*, cmp_new_*) compared byte for byte (last frame of each step)."""
import glob, os, sys
import numpy as np
from PIL import Image

OUT = (os.environ.get('PERF_AUDIT_OUT', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'out')).replace(chr(92), '/')) + '/perf_out'


def load(path):
    return np.asarray(Image.open(path).convert('RGB'), dtype=np.int16)


for scene in ('nuke', 'battle'):
    for api in ('d3d12', 'vulkan'):
        a = sorted(glob.glob('%s/cmp_old_%s_%s/*.bmp' % (OUT, scene, api)))
        b = sorted(glob.glob('%s/cmp_new_%s_%s/*.bmp' % (OUT, scene, api)))
        if not a or not b:
            print(scene, api, 'missing', len(a), len(b))
            continue
        # frames at the end of the three steps: indices from the end (1 frame a second)
        res = []
        for tag, idxs in (('wide (lights on, step 2)', (-9, -8, -7)), ('close', (-3, -2, -1))):
            for i in idxs:
                try:
                    fa, fb = load(a[i]), load(b[i])
                except Exception as e:
                    continue
                d = np.abs(fa - fb)
                res.append((tag, os.path.basename(a[i]), os.path.basename(b[i]), int(d.max()), float((d.sum(axis=2) > 0).mean() * 100)))
        # frames of one run against each other (a paused game draws the same frame)
        sa = [load(a[i]) for i in (-3, -2, -1)]
        self_diff = max(int(np.abs(sa[0] - sa[1]).max()), int(np.abs(sa[1] - sa[2]).max()))
        sb = [load(b[i]) for i in (-3, -2, -1)]
        self_diff_b = max(int(np.abs(sb[0] - sb[1]).max()), int(np.abs(sb[1] - sb[2]).max()))
        print('%s %s: frames old %d new %d; within one run (old/new) max diff %d / %d' % (scene, api, len(a), len(b), self_diff, self_diff_b))
        for r in res:
            print('   %-26s %s vs %s: max channel difference %d, pixels differing %.3f %%' % r)
