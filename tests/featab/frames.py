import sys, os, re
from PIL import Image, ImageDraw, ImageChops, ImageStat
HERE = os.path.dirname(os.path.abspath(__file__))

def frames(d, steps):
    order = re.findall(r"\{ '(\w+)',", open(os.path.join(HERE, 'featab_src', steps)).read())
    last = {}
    for n in sorted(f for f in os.listdir(d) if f.endswith('.bmp')):
        r = Image.open(os.path.join(d, n)).convert('RGB').getpixel((3, 3))
        if r[1] > 200:
            last[1 + round(r[0] / 33) + 8 * round(r[2] / 33)] = n
    return {l: os.path.join(d, last[i + 1]) for i, l in enumerate(order) if (i + 1) in last}

def load(path):
    return Image.open(path).convert('RGB')

def diff_stats(a, b):
    d = ImageChops.difference(a, b)
    mean = sum(ImageStat.Stat(d).mean) / 3
    frac = ImageStat.Stat(d.convert('L').point(lambda v: 255 if v > 8 else 0)).mean[0] / 255 * 100
    mx = max(e[1] for e in d.getextrema())
    return d, mean, frac, mx

def strip(ims, labels, out, scale=1.0):
    w, h = ims[0].size
    w, h = int(w * scale), int(h * scale)
    sheet = Image.new('RGB', (w * len(ims), h + 18), (20, 20, 20))
    dr = ImageDraw.Draw(sheet)
    for k, (im, l) in enumerate(zip(ims, labels)):
        sheet.paste(im.resize((w, h), Image.LANCZOS) if scale != 1 else im, (k * w, 18))
        dr.text((k * w + 4, 3), l, fill=(255, 255, 255))
    sheet.save(out)
    return out

if __name__ == '__main__':
    # fr.py <dumpdir> <steps.lua> <out.png> <x0,y0,x1,y1|full> <scale> label...
    d, steps, out, c, scale = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], float(sys.argv[5])
    fm = frames(d, steps)
    ims = []
    for l in sys.argv[6:]:
        im = load(fm[l])
        if c != 'full':
            im = im.crop(tuple(int(v) for v in c.split(',')))
        ims.append(im)
    print(strip(ims, sys.argv[6:], out, scale))
    for l, im in zip(sys.argv[7:], ims[1:]):
        _, m, f, mx = diff_stats(ims[0], im)
        print('%s vs %s: mean %.3f, >8 levels %.2f %%, max %d' % (l, sys.argv[6], m, f, mx))
