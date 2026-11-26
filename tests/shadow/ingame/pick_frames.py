# pick_frames.py <dumpdir> <outprefix>: groups the dump frames by the "SHADOW MODE n" label the test script draws (crop 380..760 x 150..190),
# in time order, and saves the last frame of every group as <outprefix>_<k>.png (k = order of the groups, mode 0,1,2,3,4,0).
import sys, os, glob
from PIL import Image, ImageChops, ImageStat
dump, out = sys.argv[1:3]
frames = sorted(glob.glob(os.path.join(dump, '*.bmp')), key=os.path.getmtime)
box = (380, 150, 760, 190)
groups = []
prev = None
for f in frames:
    im = Image.open(f).convert('RGB')
    crop = im.crop(box)
    lum = ImageStat.Stat(crop.convert('L'))
    has_text = lum.stddev[0] > 25 and lum.extrema[0][1] > 200
    if not has_text:
        prev = None
        continue
    if prev is None or sum(ImageStat.Stat(ImageChops.difference(crop, prev)).mean) / 3 > 0.4:
        groups.append([])
    groups[-1].append(f)
    prev = crop
for k, g in enumerate(groups):
    Image.open(g[-1]).convert('RGB').save(f'{out}_{k}.png')
    print(k, len(g), os.path.basename(g[-1]))
