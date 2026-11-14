"""Builds the editor's icon font from icons.txt: each icon's strokes are turned into outlines (1.7 wide, round ends and
joins, as the icons are drawn), merged, and written as one TrueType glyph at a private-use code point (U+E000 on, in
the list's order). Writes src/editor/ui/EdIconFont.cpp (the font's bytes) and src/editor/ui/EdIconFont.h (a UTF-8
string per icon, to put in labels: ICON_UNDO "Undo").

Needs fontTools and skia-pathops (pip install fonttools skia-pathops). Run from anywhere:
  python tools/editor/icon_font/make_icon_font.py [--ttf tmp/EdIcons.ttf]
"""
import argparse
import io
import math
import pathlib
import re
import xml.etree.ElementTree as ET

import pathops
from fontTools.fontBuilder import FontBuilder
from fontTools.pens.cu2quPen import Cu2QuPen
from fontTools.pens.transformPen import TransformPen
from fontTools.pens.ttGlyphPen import TTGlyphPen
from fontTools.svgLib.path import parse_path

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
UPM = 1000
VIEW = 24.0
STROKE = 1.7
FIRST = 0xE000
# The icon's square sits on the text's line: 80% above the baseline, 20% below.
DESCENT = 200
ASCENT = UPM - DESCENT


def number(element, name, default=0.0):
    value = element.get(name)
    return float(value) if value is not None else default


def element_path(element):
    """One SVG element as path data (the shapes the icons use)."""
    tag = element.tag
    if tag == 'path':
        return element.get('d')
    if tag == 'circle' or tag == 'ellipse':
        cx, cy = number(element, 'cx'), number(element, 'cy')
        rx = number(element, 'r', number(element, 'rx'))
        ry = number(element, 'r', number(element, 'ry'))
        return (f'M{cx - rx} {cy}a{rx} {ry} 0 1 0 {2 * rx} 0a{rx} {ry} 0 1 0 {-2 * rx} 0z')
    if tag == 'rect':
        x, y = number(element, 'x'), number(element, 'y')
        w, h = number(element, 'width'), number(element, 'height')
        r = min(number(element, 'rx', number(element, 'ry')), w / 2, h / 2)
        if r <= 0:
            return f'M{x} {y}h{w}v{h}h{-w}z'
        return (f'M{x + r} {y}h{w - 2 * r}a{r} {r} 0 0 1 {r} {r}v{h - 2 * r}a{r} {r} 0 0 1 {-r} {r}'
                f'h{-(w - 2 * r)}a{r} {r} 0 0 1 {-r} {-r}v{-(h - 2 * r)}a{r} {r} 0 0 1 {r} {-r}z')
    if tag == 'line':
        return (f"M{number(element, 'x1')} {number(element, 'y1')}L{number(element, 'x2')} {number(element, 'y2')}")
    if tag in ('polyline', 'polygon'):
        points = [float(v) for v in re.split(r'[\s,]+', element.get('points').strip())]
        d = 'M' + ' L'.join(f'{points[i]} {points[i + 1]}' for i in range(0, len(points), 2))
        return d + ('z' if tag == 'polygon' else '')
    raise SystemExit(f'unknown element {tag}')


def skia_path(d):
    path = pathops.Path()
    parse_path(d, pathops.PathPen(path))
    return path


def icon_outline(svg):
    """The icon's filled outline in the 24 x 24 view."""
    root = ET.fromstring(f'<svg>{svg}</svg>')
    pieces = []
    for element in root.iter():
        if element.tag == 'svg':
            continue
        d = element_path(element)
        fill = element.get('fill', 'none')
        stroke = element.get('stroke', 'currentColor')
        if fill != 'none':
            filled = skia_path(d)
            filled.fillType = pathops.FillType.WINDING
            pieces.append(filled)
        if stroke != 'none':
            stroked = skia_path(d)
            width = number(element, 'stroke-width', STROKE)
            stroked.stroke(width, pathops.LineCap.ROUND_CAP, pathops.LineJoin.ROUND_JOIN, 4.0)
            # Skia's round ends are conics; the union and TrueType take quadratics.
            stroked.convertConicsToQuads(0.01)
            # A path's strokes overlap each other (grid: the square and the lines across it): one shape first, by the
            # non-zero rule, so the union below doesn't read the overlaps as holes.
            stroked.fillType = pathops.FillType.WINDING
            stroked.simplify(fix_winding=True)
            pieces.append(stroked)
    result = pathops.Path()
    builder = pathops.OpBuilder(fix_winding=True, keep_starting_points=False)
    for piece in pieces:
        builder.add(piece, pathops.PathOp.UNION)
    result = builder.resolve()
    return result


def glyph_of(outline):
    pen = TTGlyphPen(None)
    scale = UPM / VIEW
    # The view's y runs down; the font's up, its baseline DESCENT above the square's foot.
    flip = TransformPen(Cu2QuPen(pen, max_err=0.5, reverse_direction=True), (scale, 0, 0, -scale, 0, ASCENT))
    outline.draw(flip)
    return pen.glyph()


def constant(name):
    return 'ICON_' + re.sub(r'([a-z])([A-Z])', r'\1_\2', name).upper()


def main():
    parser = argparse.ArgumentParser(description='Builds the editor icon font from icons.txt.')
    parser.add_argument('--ttf', help='also write the font file here (to look at it)')
    args = parser.parse_args()
    icons = []
    for line in (HERE / 'icons.txt').read_text(encoding='utf-8').splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        name, svg = line.split('\t', 1)
        icons.append((name, svg))

    order = ['.notdef'] + [f'icon_{name}' for name, _ in icons]
    glyphs = {'.notdef': TTGlyphPen(None).glyph()}
    metrics = {'.notdef': (UPM, 0)}
    cmap = {}
    for i, (name, svg) in enumerate(icons):
        glyph = glyph_of(icon_outline(svg))
        glyphs[f'icon_{name}'] = glyph
        metrics[f'icon_{name}'] = (UPM, 0)
        cmap[FIRST + i] = f'icon_{name}'

    builder = FontBuilder(UPM, isTTF=True)
    builder.setupGlyphOrder(order)
    builder.setupCharacterMap(cmap)
    builder.setupGlyf(glyphs)
    for name in order:
        glyph = glyphs[name]
        glyph.recalcBounds(builder.font['glyf'])
        metrics[name] = (UPM, getattr(glyph, 'xMin', 0))
    builder.setupHorizontalMetrics(metrics)
    builder.setupHorizontalHeader(ascent=ASCENT, descent=-DESCENT)
    builder.setupNameTable({'familyName': 'FAF Editor Icons', 'styleName': 'Regular'})
    builder.setupOS2(sTypoAscender=ASCENT, sTypoDescender=-DESCENT, sTypoLineGap=0, usWinAscent=ASCENT,
                     usWinDescent=DESCENT)
    builder.setupPost()
    data = io.BytesIO()
    builder.save(data)
    font = data.getvalue()

    ui = ROOT / 'src' / 'editor' / 'ui'
    rows = []
    for i in range(0, len(font), 24):
        rows.append('  ' + ', '.join(f'0x{b:02x}' for b in font[i:i + 24]) + ',')
    (ui / 'EdIconFont.cpp').write_text(
        '// Generated by tools/editor/icon_font/make_icon_font.py from icons.txt; do not edit.\n'
        '#include "editor/ui/EdIconFont.h"\n\n'
        'namespace faf::editor\n{\n'
        '  namespace\n  {\n'
        f'    const unsigned char kIconFont[{len(font)}] = {{\n' + '\n'.join('  ' + r for r in rows) + '\n    };\n'
        '  } // namespace\n\n'
        '  const unsigned char* IconFontData()\n  {\n    return kIconFont;\n  }\n\n'
        f'  int IconFontSize()\n  {{\n    return {len(font)};\n  }}\n'
        '} // namespace faf::editor\n',
        encoding='utf-8', newline='\n')
    lines = [
        '// Generated by tools/editor/icon_font/make_icon_font.py from icons.txt; do not edit.',
        '#pragma once',
        '',
        '/*',
        ' * The editor\'s icons as text: each is one private-use character (U+E000 on) of the icon font merged into the',
        ' * panels\' font (EdApp), so a label can carry one: ICON_UNDO " Undo". The icons are the mockup\'s line icons.',
        ' */',
    ]
    for i, (name, _) in enumerate(icons):
        utf8 = chr(FIRST + i).encode('utf-8')
        lines.append(f'#define {constant(name)} "' + ''.join(f'\\x{b:02x}' for b in utf8) + '"')
    lines += [
        f'#define ICON_FIRST 0x{FIRST:04X}',
        f'#define ICON_LAST 0x{FIRST + len(icons) - 1:04X}',
        '',
        'namespace faf::editor',
        '{',
        '  /** The icon font (TrueType), embedded. */',
        '  [[nodiscard]] const unsigned char* IconFontData();',
        '  [[nodiscard]] int IconFontSize();',
        '} // namespace faf::editor',
        '',
    ]
    (ui / 'EdIconFont.h').write_text('\n'.join(lines), encoding='utf-8', newline='\n')
    if args.ttf:
        pathlib.Path(args.ttf).write_bytes(font)
    print(f'{len(icons)} icons, {len(font)} bytes')


if __name__ == '__main__':
    main()
