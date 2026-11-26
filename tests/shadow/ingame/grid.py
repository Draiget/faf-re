import sys
from PIL import Image, ImageDraw
prefix, out, box, scale = sys.argv[1], sys.argv[2], tuple(int(v) for v in sys.argv[3].split(',')), float(sys.argv[4])
labels = sys.argv[5:]   # k:text
tiles = []
for l in labels:
    k, t = l.split(':')
    im = Image.open(f'{prefix}_{k}.png').convert('RGB').crop(box)
    im = im.resize((int(im.width * scale), int(im.height * scale)), Image.BICUBIC)
    ImageDraw.Draw(im).text((6, 6), t, fill=(255, 255, 0))
    tiles.append(im)
w, h = tiles[0].size
cols = 2
rows = (len(tiles) + 1) // 2
sheet = Image.new('RGB', (cols * w + 6, rows * h + 6 * (rows - 1)), (255, 255, 255))
for i, t in enumerate(tiles):
    sheet.paste(t, ((i % cols) * (w + 6), (i // cols) * (h + 6)))
sheet.save(out)
