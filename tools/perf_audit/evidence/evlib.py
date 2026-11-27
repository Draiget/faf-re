import json, os, re, datetime
from PIL import Image, ImageChops

def load_run(d):
    return json.load(open(os.path.join(d, 'run.json')))

def scene_frames(d, hold_default=5):
    """{scene label: dump path}: the dump written about 1.5 s before the scene's hold ends (scenes hold at least 4 s on a paused game)."""
    r = load_run(d)
    t0 = datetime.datetime.fromisoformat(r['start'])
    dumps = [(datetime.datetime.fromisoformat(x['mt']), x['f']) for x in r['dumps']]
    out = {}
    marks = [(k, v) for k, v in r['markers'].items() if k.startswith('scene')]
    done = r['markers'].get('done')
    for i, (k, v) in enumerate(marks):
        label = k.split(' ', 2)[2]
        end = marks[i + 1][1] if i + 1 < len(marks) else (done if done else v + 5)
        target = t0 + datetime.timedelta(seconds=v + 2.5)
        best = min(dumps, key=lambda x: abs((x[0] - target).total_seconds()))
        out[label] = os.path.join(d, best[1])
    return out

def diff_share(a, b, thr=8):
    A = Image.open(a).convert('RGB'); B = Image.open(b).convert('RGB')
    if A.size != B.size: return None
    d = ImageChops.difference(A, B).convert('L')
    h = d.histogram()
    n = A.size[0] * A.size[1]
    return sum(h[thr + 1:]) / n
