"""Generate original, code-drawn metal UI textures (no external artwork or fonts)."""
from pathlib import Path
import random
from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parents[1]/'mods/Microchip-Eco-Sharing/textures'
OUT.mkdir(parents=True,exist_ok=True)
S=2


def canvas(w,h):
    im=Image.new('RGBA',(w*S,h*S)); return im,ImageDraw.Draw(im)


def poly(d,points,fill,outline=None,width=1):
    points=[(round(x*S),round(y*S)) for x,y in points]
    d.polygon(points,fill=fill)
    if outline: d.line(points+[points[0]],fill=outline,width=width*S,joint='curve')


def line(d,points,fill,width=1):
    d.line([(round(x*S),round(y*S)) for x,y in points],fill=fill,width=width*S,joint='curve')


def plate(d,x,y,w,h,fill,edge,cut=8,width=1):
    poly(d,[(x+cut,y),(x+w-cut,y),(x+w,y+cut),(x+w,y+h-cut),
            (x+w-cut,y+h),(x+cut,y+h),(x,y+h-cut),(x,y+cut)],fill,edge,width)


def save(im,name):
    im.resize((im.width//S,im.height//S),Image.Resampling.LANCZOS).save(OUT/(name+'.dds'))


im,d=canvas(940,660)
plate(d,1,1,937,657,'#101312','#656c68',20,2)
plate(d,7,7,925,645,'#343b35','#90988d',17,2)
plate(d,12,12,915,635,'#490e0a','#f25b40',14,2)
plate(d,18,18,903,623,'#8d2417','#b63020',12,3)
plate(d,25,25,889,609,'#171c17','#080d09',10,3)
# Subtle deterministic grain, kept off the rails and all functional text.
rng=random.Random(2401)
for _ in range(28000):
    x,y=rng.randrange(31,909),rng.randrange(31,628)
    c=rng.randrange(20,39)
    d.point((x*S,y*S),fill=(c,c+3,c,255))
for y in range(32,630,4): line(d,[(31,y),(908,y)],'#20251e')
line(d,[(31,103),(909,103)],'#0b110b',3)
line(d,[(125,104),(904,104)],'#899b39')
line(d,[(125,108),(904,108)],'#323e20')
# Red panel rails, bolts and recessed corner joints.
for x,y in [(8,26),(8,605),(905,26),(905,605)]:
    plate(d,x,y,26,29,'#313732','#94998c',4)
    line(d,[(x+6,y+9),(x+19,y+9)],'#0a0d0a',3)
for x in [100,438,771]:
    plate(d,x,638,76,12,'#111611','#9d4632',4)
    for n in range(5):
        a=x+8+n*12
        poly(d,[(a,640),(a+6,640),(a-1,648),(a-7,648)],'#8b6b21')
for x in [46,895]:
    for y in [36,617]:
        d.ellipse((x*S,y*S,(x+5)*S,(y+5)*S),fill='#080c08',outline='#687366',width=S)
save(im,'frame')

im,d=canvas(880,148)
plate(d,0,0,879,147,'#080e09','#7a873e',10,2)
plate(d,5,5,869,137,'#141b12','#353e2c',7)
poly(d,[(12,0),(283,0),(301,25),(12,25)],'#263014','#aaba54')
line(d,[(18,27),(861,27)],'#5e6a32')
line(d,[(15,88),(863,88)],'#313b27')
save(im,'reserves')

im,d=canvas(425,282)
plate(d,0,0,424,281,'#0a100b','#849140',10,2)
plate(d,5,5,414,271,'#111912','#38442b',7)
poly(d,[(10,0),(292,0),(309,27),(10,27)],'#243015','#b0bd53')
line(d,[(14,62),(409,62)],'#59633a')
for y in range(91,265,29): line(d,[(14,y),(409,y)],'#2d3828')
save(im,'allies')

im,d=canvas(435,282)
plate(d,0,0,434,281,'#0a100b','#849140',10,2)
plate(d,5,5,424,271,'#111912','#38442b',7)
poly(d,[(10,0),(405,0),(424,27),(10,27)],'#243015','#b0bd53')
line(d,[(15,111),(419,111)],'#58683b')
for y in range(151,277,25): line(d,[(15,y),(419,y)],'#2d3828')
save(im,'priority')

for state,edge,fill in [('up','#8d986a','#22291d'),('over','#dcf768','#364b16'),('down','#96b52e','#18240b'),('apply','#d5f758','#3f610d')]:
    im,d=canvas(220,42)
    plate(d,0,0,219,41,'#10150e','#67705c',8,2)
    plate(d,4,4,211,33,fill,edge,5,2)
    line(d,[(11,8),(207,8)],'#5b6b3b')
    line(d,[(11,36),(207,36)],'#070d06',2)
    save(im,'button-'+state)

for checked in [False,True]:
    im,d=canvas(32,32)
    plate(d,1,1,29,29,'#10180b','#a5b447' if checked else '#6a735a',5,2)
    plate(d,5,5,21,21,'#314b0c' if checked else '#1b2119','#556b23' if checked else '#30392a',2)
    if checked:
        line(d,[(7,16),(13,23),(26,8)],'#b8ee32',5)
        line(d,[(8,15),(13,20),(25,8)],'#f5ffc4',2)
    save(im,'check-on' if checked else 'check-off')

for state,fill in [('up','#9abb20'),('over','#d7f958'),('down','#6a8f11')]:
    im,d=canvas(26,34)
    plate(d,1,1,23,31,'#25320b','#e3ef91',5,2)
    plate(d,5,4,15,25,fill,'#a9c64a',3)
    line(d,[(7,7),(17,7)],'#edffa8',2)
    save(im,'thumb-'+state)

for resource in ['energy','mass']:
    im,d=canvas(36,38)
    if resource=='energy':
        poly(d,[(19,1),(6,22),(16,22),(11,37),(32,14),(22,14),(27,1)],'#deef4c','#6c791f')
    else:
        for x,y in [(8,2),(0,18),(18,18)]:
            poly(d,[(x+8,y),(x+15,y+4),(x+15,y+13),(x+8,y+17),(x,y+13),(x,y+4)],'#cad1b8','#737b61')
    save(im,resource)

im,d=canvas(88,76)
for x in [27,35,43,51]:
    line(d,[(x,4),(x,13)],'#deef65',2); line(d,[(x,35),(x,44)],'#deef65',2)
for y in [17,24,31]:
    line(d,[(16,y),(25,y)],'#deef65',2); line(d,[(55,y),(64,y)],'#deef65',2)
plate(d,25,12,30,26,'#28350c','#d5ec5b',1,2)
line(d,[(4,45),(4,30),(12,22)],'#a7ca30',4)
poly(d,[(4,17),(17,20),(10,31)],'#dbed56')
line(d,[(66,33),(78,42),(78,55)],'#a7ca30',4)
poly(d,[(68,52),(82,52),(76,65)],'#dbed56')
poly(d,[(19,46),(9,62),(18,62),(14,75),(32,55),(24,55),(29,46)],'#dceb58')
for x,y in [(47,47),(41,62),(58,62)]:
    poly(d,[(x+7,y),(x+13,y+4),(x+13,y+11),(x+7,y+15),(x,y+11),(x,y+4)],'#c4dc43','#96ab32')
save(im,'logo')

for symbol in ['up','down','close']:
    im,d=canvas(24,24)
    if symbol=='up': poly(d,[(3,18),(12,5),(21,18)],'#d9ed65')
    elif symbol=='down': poly(d,[(3,6),(12,19),(21,6)],'#d9ed65')
    else:
        plate(d,0,0,23,23,'#200b08','#bc3e29',4,2)
        line(d,[(6,6),(17,17)],'#ff5133',3);line(d,[(6,17),(17,6)],'#ff5133',3)
    save(im,symbol)

# Native combo boxes take split images; only the centre stretches.
for state,edge in [('up','#94a344'),('over','#ddf86d'),('down','#bbd351'),('dis','#515943')]:
    for part,w in [('left',8),('mid',16),('right',28)]:
        im,d=canvas(w,36)
        d.rectangle((0,0,w*S-1,36*S-1),fill='#17200d')
        line(d,[(0,1),(w,1)],edge,2);line(d,[(0,34),(w,34)],edge,2)
        if part=='left': line(d,[(1,1),(1,34)],edge,2)
        if part=='right':
            line(d,[(w-2,1),(w-2,34)],edge,2)
            poly(d,[(5,13),(19,13),(12,23)],'#ddeb74')
        save(im,'combo-'+part+'-'+state)
for part in ['ul','um','ur','l','m','r','ll','lm','lr']:
    im,d=canvas(8,8);d.rectangle((0,0,15,15),fill='#17200d')
    if part in ['ul','um','ur']:line(d,[(0,1),(8,1)],'#9bab4e',2)
    if part in ['ll','lm','lr']:line(d,[(0,7),(8,7)],'#9bab4e',2)
    if part in ['ul','l','ll']:line(d,[(1,0),(1,8)],'#9bab4e',2)
    if part in ['ur','r','lr']:line(d,[(7,0),(7,8)],'#9bab4e',2)
    save(im,'list-'+part)
print('Generated',len(list(OUT.glob('*.dds'))),'original UI textures')
