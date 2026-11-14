"""Render an illustrative UI mockup, not a recording of the game. Requires Pillow."""
from pathlib import Path
import math
import random
from PIL import Image, ImageDraw, ImageFont, ImageFilter

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT.parents[1] / 'output'
OUT.mkdir(exist_ok=True)
W, H = 1120, 630
INK, MUTED, CYAN = '#f1f6ff', '#9fb1c2', '#59e0cf'
FONTS = Path('C:/Windows/Fonts')


def font(size, bold=False):
    return ImageFont.truetype(str(FONTS / ('segoeuib.ttf' if bold else 'segoeui.ttf')), size)


def text(draw, at, value, size=16, color=INK, bold=False):
    draw.text(at, value, fill=color, font=font(size, bold))


def box(draw, rect, fill, outline=None, radius=8):
    draw.rounded_rectangle(rect, radius, fill=fill, outline=outline, width=1)


def backdrop():
    random.seed(19)
    im = Image.new('RGB', (W, H), '#22302e')
    d = ImageDraw.Draw(im)
    for _ in range(120):
        x, y = random.randrange(W), random.randrange(40, H)
        r = random.randrange(15, 130)
        shade = random.choice(['#263730', '#2b3b32', '#28372d', '#1b2c2b'])
        d.ellipse((x-r, y-r/3, x+r, y+r/3), fill=shade)
    d.polygon([(0, 350), (310, 298), (650, 370), (1120, 230), (1120, 358), (685, 448), (280, 375), (0, 430)], fill='#1a333e')
    d.line([(0, 355), (310, 305), (650, 377), (1120, 237)], fill='#3b5150', width=7)
    d.line([(0, 420), (280, 367), (685, 439), (1120, 350)], fill='#344948', width=8)
    for x in range(0, W, 56):
        d.line((x, 56, x, H), fill='#2c3c36', width=1)
    for y in range(56, H, 56):
        d.line((0, y, W, y), fill='#2c3c36', width=1)
    # Bases, unit formations and strategic markers give the HUD a game context.
    for x, y, color in [(346, 268, '#6cd9f5'), (794, 371, '#ff9e65')]:
        for dx, dy, r in [(0,0,24),(-48,24,13),(48,24,13),(0,-48,12),(-45,-36,10),(45,-36,10)]:
            d.rectangle((x+dx-r, y+dy-r, x+dx+r, y+dy+r), fill='#15222b', outline=color, width=2)
            d.line((x+dx-r+5,y+dy,x+dx+r-5,y+dy), fill=color, width=2)
        for i in range(16):
            px, py = x+random.randrange(-130, 130), y+random.randrange(40, 120)
            d.polygon([(px,py-5),(px+5,py),(px,py+5),(px-5,py)], fill=color)
    for x, y in [(478, 330), (580, 300), (690, 335)]:
        d.ellipse((x-13,y-13,x+13,y+13), outline='#77c3ba', width=1)
        d.rectangle((x-3,y-3,x+3,y+3), fill='#a6dfb4')
    # Top HUD.
    d.rectangle((0,0,W,55), fill='#0b121b')
    d.line((0,55,W,55), fill='#425565', width=2)
    box(d,(16,11,168,43),'#172532','#35485b')
    text(d,(28,17),'UEF  /  MICROCHIP',13,bold=True)
    for x, title, value, color in [(196,'MASS','+42  /  1.6K','#8dc8aa'),(433,'ENERGY','+1.2K  /  8.4K','#f7d477')]:
        text(d,(x,9),title,10,MUTED,True); text(d,(x,24),value,16,color,True)
        d.rectangle((x+135,27,x+205,33),fill='#263b43');d.rectangle((x+135,27,x+188,33),fill=color)
    text(d,(724,19),'00:24:18',17,bold=True)
    text(d,(924,18),'MENU    /    F11',13,MUTED)
    # Minimap and bottom controls.
    box(d,(16,430,182,596),'#10202a','#526778')
    d.polygon([(28,504),(70,475),(120,519),(170,479),(170,506),(125,540),(75,500),(28,527)],fill='#264651')
    for x,y,c in [(65,476,'#6cd9f5'),(136,548,'#ff9e65'),(99,510,'#a6dfb4')]:
        d.rectangle((x-4,y-4,x+4,y+4),fill=c)
    text(d,(30,572),'TACTICAL MAP',10,MUTED,True)
    box(d,(201,528,707,598),'#0d1721','#384b59')
    text(d,(217,538),'LAND FACTORY',12,MUTED,True)
    for i in range(7):
        x=219+i*65
        box(d,(x,559,x+48,588),'#20333f','#3d5868',3)
        d.polygon([(x+15,579),(x+24,566),(x+33,579)],outline='#8abcc9')
    box(d,(844,453,1102,598),'#0c1720','#354b5c')
    text(d,(860,466),'ALLIED CHAT',11,CYAN,True)
    text(d,(860,494),'Nova: scouts on the east side',13)
    text(d,(860,518),'Atlas: moving tanks north',13)
    text(d,(860,542),'Rook: air ready in 30 seconds',13)
    d.rectangle((0,610,W,H),fill='#080f17')
    text(d,(18,613),'MICROCHIP CHAT MENTION',10,CYAN,True)
    text(d,(760,613),'UI MOCKUP  /  NOT CAPTURED GAMEPLAY',10,MUTED)
    return im


BASE = backdrop()


def popup(seconds, y=78, second=False, cursor=None, opacity=1):
    im = BASE.copy()
    d=ImageDraw.Draw(im)
    x,w,h=240,640,126
    shadow=Image.new('RGBA',im.size)
    sd=ImageDraw.Draw(shadow);sd.rounded_rectangle((x-8,y+5,x+w+8,y+h+14),10,fill=(0,0,0,140))
    im=Image.alpha_composite(im.convert('RGBA'),shadow.filter(ImageFilter.GaussianBlur(10)))
    d=ImageDraw.Draw(im)
    box(d,(x,y,x+w,y+h),'#0c1520','#30475a')
    d.rounded_rectangle((x,y,x+4,y+h),2,fill=CYAN)
    text(d,(x+23,y+12),'Rook' if second else 'Atlas',12,CYAN,True)
    text(d,(x+23,y+43),'MC, air support is ready. Ping your target.' if second else 'Microchip, can you cover the north side?',17)
    text(d,(x+w-96,y+95),f'{seconds}s left',11,MUTED)
    box(d,(x+w-37,y+9,x+w-9,y+37),'#1d2b3b',radius=3)
    d.line((x+w-28,y+18,x+w-18,y+28),fill='#c4d2e0',width=2)
    d.line((x+w-18,y+18,x+w-28,y+28),fill='#c4d2e0',width=2)
    d.rectangle((x+4,y+h-3,x+w,y+h),fill='#263645')
    d.rectangle((x+4,y+h-3,x+4+(w-4)*seconds/10,y+h),fill=CYAN)
    if cursor:
        cx,cy=cursor
        d.polygon([(cx,cy),(cx+1,cy+19),(cx+6,cy+14),(cx+10,cy+23),(cx+14,cy+21),(cx+10,cy+12),(cx+18,cy+12)],fill='white',outline='#0a111b')
    return Image.blend(BASE, im.convert('RGB'), opacity)


frames, durations = [], []


def add(im, duration):
    frames.append(im); durations.append(duration)


def slide(second=False, out=False):
    count=6 if out else 9
    for i in range(1,count+1):
        p=i/count
        if out:
            ease=p*p*(3-2*p)
            y,alpha=78-22*ease,1-ease
        else:
            t=p-1
            ease=1+2.1*t*t*t+1.1*t*t
            y,alpha=50+28*ease,1-(1-p)**3
        add(popup(0 if out else 10,round(y),second,opacity=alpha),40)


add(BASE,1100)
slide()
for remaining in range(10,0,-1): add(popup(remaining),1000)
slide(out=True)
add(BASE,700)
slide(second=True)
add(popup(10,second=True),1000)
add(popup(9,second=True),700)
for i in range(1,9):
    p=i/8
    add(popup(8,second=True,cursor=(round(950+(855-950)*p),round(340+(98-340)*p))),50)
add(popup(8,second=True,cursor=(855,98)),180)
slide(second=True,out=True)
add(BASE,650)

# Last view demonstrates the menu settings that the actual mod exposes.
im=BASE.convert('RGBA')
veil=Image.new('RGBA',im.size,(0,0,0,140));im=Image.alpha_composite(im,veil)
d=ImageDraw.Draw(im)
box(d,(250,76,870,544),'#0c1520','#3a5264')
text(d,(272,91),'Microchip Chat Mention',24,CYAN,True)
text(d,(272,129),'Player name is automatic; nicknames are additional matches.',13,MUTED)
text(d,(272,159),'Your player name: Microchip',14)
text(d,(272,196),'Nicknames (separate with commas)',15)
box(d,(272,223,838,251),'#182635','#355368',4);text(d,(284,225),'MC, David',16)
text(d,(272,268),'Display time in seconds (1-120)',15)
box(d,(645,263,730,291),'#182635','#355368',4);text(d,(674,264),'10',16,CYAN,True)
text(d,(272,308),'Message font size (12-32)',15)
box(d,(645,303,730,331),'#182635','#355368',4);text(d,(674,304),'17',16,CYAN,True)
for y,label in [(350,'Enable chat mention popups'),(385,'Simulation mode - local test every 10 seconds'),(420,'Play notification sound when a message pops up')]:
    box(d,(272,y,295,y+23),'#263b4b',radius=2)
    text(d,(277,y-1),'X',17,CYAN,True);text(d,(307,y+1),label,15)
text(d,(272,461),'Changes take effect after Save. Test messages are never sent to players.',12,MUTED)
for x,label in [(272,'Test Popup'),(466,'Save'),(660,'Close')]:
    box(d,(x,492,x+176,529),'#204641' if label=='Save' else '#1d2b3b','#3a5264',4)
    text(d,(x+48,499),label,15,CYAN if label=='Save' else INK,True)
add(im.convert('RGB'),2800)

gif=OUT/'Microchip-Chat-Mention-mockup.gif'
# A common palette keeps the unchanged battlefield stable between frames.
palette=frames[8].quantize(colors=128)
indexed=[frame.quantize(palette=palette,dither=Image.Dither.NONE) for frame in frames]
indexed[0].save(gif,save_all=True,append_images=indexed[1:],duration=durations,loop=0,optimize=True,disposal=1)
popup(10).save(OUT/'Microchip-Chat-Mention-preview.png')

icon=Image.new('RGB',(128,128),'#0c1520');d=ImageDraw.Draw(icon)
box(d,(4,4,123,123),'#132333','#59e0cf',18)
text(d,(19,6),'@',70,CYAN,True);text(d,(31,91),'MC',21,bold=True)
icon.save(ROOT/'icon.png')
print(f'{gif} ({gif.stat().st_size:,} bytes, {sum(durations)/1000:.1f}s)')
