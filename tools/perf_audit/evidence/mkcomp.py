"""mkcomp.py: composites master | PR defaults | PR switches off | PR features on (full frame + crop) and stats (pixel share with a channel diff > 8/255) for every PR.
Output frames/<pr>/<group>_<api>_<scene>.png and frames/<pr>/stats.json"""
import sys, os, json
from PIL import Image, ImageChops, ImageDraw
import evlib
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'frames')
LABEL = {'nowater_wide': 'lake_wide', 'nowater_mid': 'lake_mid'}
ONSCENE = lambda s: s + '_on'

def region_share(a, b, crop=None, thr=8):
    A = Image.open(a).convert('RGB'); B = Image.open(b).convert('RGB')
    if A.size != B.size: return None
    if crop: A = A.crop(crop); B = B.crop(crop)
    h = ImageChops.difference(A, B).convert('L').histogram()
    return sum(h[thr + 1:]) / (A.size[0] * A.size[1])

def blur_share(a, b, thr=8, r=12):
    from PIL import ImageFilter
    A = Image.open(a).convert('RGB'); B = Image.open(b).convert('RGB')
    if A.size != B.size: return None
    A = A.filter(ImageFilter.BoxBlur(r)); B = B.filter(ImageFilter.BoxBlur(r))
    h = ImageChops.difference(A, B).convert('L').histogram()
    return sum(h[thr + 1:]) / (A.size[0] * A.size[1])

def frames(tag, group, api):
    d = os.path.join(HERE, 'out', tag, '%s_%s' % (group, api))
    try:
        return evlib.scene_frames(d) if os.path.exists(os.path.join(d, 'run.json')) else {}
    except Exception as e:
        return {}

def pct(v): return None if v is None else round(100 * v, 2)

def comp(pr, group, api, scene, crop):
    ma = frames('master_a', group, api).get(scene); mb = frames('master_b', group, api).get(scene)
    p = frames(pr, group, api); pb = frames(pr + '_b', group, api).get(scene)
    d = p.get(scene); o = p.get(scene + '_off'); on = frames(pr + '_on', group, api).get(ONSCENE(scene))
    if not (ma and d): return None
    cols = [('master', ma), (pr.upper() + ' defaults', d)]
    if o: cols.append((pr.upper() + ' switches off', o))
    if on: cols.append((pr.upper() + ' features on', on))
    W, H = 480, 270
    sheet = Image.new('RGB', (W * len(cols), H * 2), (20, 20, 20))
    for i, (lab, path) in enumerate(cols):
        im = Image.open(path).convert('RGB')
        full = im.resize((W, H), Image.LANCZOS); cr = im.crop(crop).resize((W, H), Image.LANCZOS)
        dr = ImageDraw.Draw(full)
        sx, sy = W / im.size[0], H / im.size[1]
        dr.rectangle([crop[0] * sx, crop[1] * sy, crop[2] * sx, crop[3] * sy], outline=(255, 255, 0), width=2)
        dr.text((8, 6), lab, fill=(255, 255, 255))
        sheet.paste(full, (i * W, 0)); sheet.paste(cr, (i * W, H))
    os.makedirs(os.path.join(OUT, pr), exist_ok=True)
    name = '%s_%s_%s.png' % (group, api, LABEL.get(scene, scene))
    sheet.quantize(256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE).save(os.path.join(OUT, pr, name), optimize=True)
    def both(a, b):
        if not (a and b): return None
        return [pct(region_share(a, b)), pct(region_share(a, b, crop)), pct(blur_share(a, b))]
    pv = frames(PREV[pr], group, api).get(scene)
    return {'scene': LABEL.get(scene, scene), 'group': group, 'api': api, 'file': name,
            'defaults_vs_prev': both(pv, d), 'on_vs_defaults': both(d, on), 'off_vs_defaults': both(d, o),
            'defaults_vs_master': both(ma, d), 'off_vs_master': both(ma, o), 'on_vs_master': both(ma, on),
            'repeat_same_build': both(d, pb), 'repeat_master': both(ma, mb)}

PREV = {'pr02': 'master_a', 'pr03': 'pr02', 'pr04': 'pr03', 'pr05': 'pr04', 'pr06': 'pr05', 'pr07': 'pr06', 'pr08': 'pr07', 'pr09': 'pr08'}
PLAN = {
    'pr02': {'sr': ['ships', 'coast_far', 'coast_near'], 'astro': ['nowater_wide', 'nowater_mid'], 'levels': ['overview', 'mid']},
    'pr03': {'sr': ['ships', 'coast_near'], 'astro': ['nowater_wide', 'nowater_mid'], 'levels': ['overview']},
    'pr04': {'sr': ['ships', 'coast_near'], 'astro': ['nowater_wide', 'nowater_mid']},
    'pr05': {'sr': ['ships', 'coast_near'], 'astro': ['nowater_wide', 'nowater_mid']},
    'pr06': {'sr': ['ships', 'coast_near'], 'astro': ['nowater_wide', 'nowater_mid']},
    'pr07': {'sr': ['ships', 'coast_far', 'coast_near'], 'levels': ['overview', 'mid']},
    'pr08': {'rivers': ['overview', 'mid']},
    'pr09': {'rivers': ['overview', 'mid'], 'levels': ['overview']},
}
CROP = {'ships': (520, 80, 1000, 350)}
if __name__ == '__main__':
    only = sys.argv[1:]
    for pr, groups in PLAN.items():
        if only and pr not in only: continue
        res = []
        for api in ('d3d11', 'd3d12', 'vulkan'):
            for g, scenes in groups.items():
                for s in scenes:
                    st = comp(pr, g, api, s, CROP.get(s, (560, 300, 1040, 570)))
                    if st: res.append(st)
        os.makedirs(os.path.join(OUT, pr), exist_ok=True)
        json.dump(res, open(os.path.join(OUT, pr, 'stats.json'), 'w'), indent=1)
        print(pr, len(res))
