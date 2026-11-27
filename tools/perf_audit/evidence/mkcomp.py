"""mkcomp.py <pr tag> <group> <api> <scene> [crop x0,y0,x1,y1]: composite of master / PR defaults / PR switches off (full frame + crop), stats as json.
Output: evidence/<pr tag>/<group>_<api>_<scene>.png and a stats entry in evidence/<pr tag>/stats.json"""
import sys, os, json
from PIL import Image, ImageChops, ImageDraw
import evlib
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'evidence')

def share(a, b, thr=8):
    A = Image.open(a).convert('RGB'); B = Image.open(b).convert('RGB')
    if A.size != B.size: return None
    d = ImageChops.difference(A, B).convert('L').point(lambda v: 255 if v > thr else 0)
    return sum(1 for p in d.getdata() if p) / (A.size[0] * A.size[1])

def frames(tag, group, api):
    d = os.path.join(HERE, 'out', tag, '%s_%s' % (group, api))
    return evlib.scene_frames(d) if os.path.exists(os.path.join(d, 'run.json')) else {}

PREV = {'pr02': 'master_a', 'pr03': 'pr02', 'pr04': 'pr03', 'pr05': 'pr04', 'pr06': 'pr05', 'pr07': 'pr06', 'pr08': 'pr07', 'pr09': 'pr08'}


def comp(pr, group, api, scene, crop=(560, 300, 1040, 570), offscene=None):
    ma = frames('master_a', group, api).get(scene)
    mb = frames('master_b', group, api).get(scene)
    p = frames(pr, group, api)
    d = p.get(scene); o = p.get(offscene or scene + '_off')
    if not (ma and d): return None
    labels = ['master', pr + ' defaults', pr + ' switches off']
    paths = [ma, d, o]
    ims = [Image.open(x).convert('RGB') if x else None for x in paths]
    W, H = 640, 360
    sheet = Image.new('RGB', (W * 3, H * 2), (20, 20, 20))
    for i, im in enumerate(ims):
        if im is None: continue
        full = im.resize((W, H), Image.LANCZOS)
        cr = im.crop(crop).resize((W, H), Image.LANCZOS)
        dr = ImageDraw.Draw(full)
        x0, y0, x1, y1 = [int(v * W / im.size[0]) if k % 2 == 0 else int(v * H / im.size[1]) for k, v in enumerate(crop)]
        dr.rectangle([x0, y0, x1, y1], outline=(255, 255, 0), width=2)
        dr.text((8, 6), labels[i], fill=(255, 255, 255))
        sheet.paste(full, (i * W, 0)); sheet.paste(cr, (i * W, H))
    os.makedirs(os.path.join(OUT, pr), exist_ok=True)
    name = '%s_%s_%s.png' % (group, api, scene)
    sheet.quantize(256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE).save(os.path.join(OUT, pr, name), optimize=True)
    pv = frames(PREV[pr], group, api).get(scene)
    st = {'scene': scene, 'group': group, 'api': api, 'file': name, 'prev': PREV[pr], 'off_vs_prev': share(pv, o) if (pv and o) else None, 'defaults_vs_prev': share(pv, d) if pv else None,
          'defaults_vs_master': share(ma, d), 'off_vs_master': share(ma, o) if o else None,
          'noise_master_vs_master': share(ma, mb) if mb else None}
    return st


def wqsheet(pr, api, crop=(520, 80, 1000, 350)):
    ma = frames('master_a', 'sr', api).get('ships')
    p = frames(pr, 'sr', api)
    paths = [('master', ma)] + [('Water Quality %s' % n, p.get('wq%d' % i)) for i, n in enumerate(('0 Off', '1 Low', '2 Medium', '3 High'))]
    W, H = 640, 360
    sheet = Image.new('RGB', (W * 5, H * 2), (20, 20, 20))
    for i, (lab, path) in enumerate(paths):
        if not path: continue
        im = Image.open(path).convert('RGB')
        full = im.resize((W, H), Image.LANCZOS)
        cr = im.crop(crop).resize((W, H), Image.LANCZOS)
        ImageDraw.Draw(full).text((8, 6), lab, fill=(255, 255, 255))
        sheet.paste(full, (i * W, 0)); sheet.paste(cr, (i * W, H))
    os.makedirs(os.path.join(OUT, pr), exist_ok=True)
    name = 'sr_%s_waterquality.png' % api
    sheet.quantize(256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE).save(os.path.join(OUT, pr, name), optimize=True)
    return {'scene': 'waterquality', 'group': 'sr', 'api': api, 'file': name}


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


def build_all(prs=None):
    out = {}
    for pr, groups in PLAN.items():
        if prs and pr not in prs: continue
        res = []
        for api in ('d3d11', 'd3d12', 'vulkan'):
            for g, scenes in groups.items():
                for s in scenes:
                    st = comp(pr, g, api, s, crop=CROP.get(s, (560, 300, 1040, 570)))
                    if st: res.append(st)
            if pr == 'pr02':
                res.append(wqsheet(pr, api))
        os.makedirs(os.path.join(OUT, pr), exist_ok=True)
        json.dump(res, open(os.path.join(OUT, pr, 'stats.json'), 'w'), indent=1)
        out[pr] = res
    return out

if __name__ == '__main__' and len(sys.argv) > 1 and sys.argv[1] == 'all':
    r = build_all()
    for pr, v in r.items(): print(pr, len(v))
