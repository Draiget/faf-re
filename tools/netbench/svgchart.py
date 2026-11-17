"""Small dependency-free SVG charts for the network report: line charts and grouped bar charts.

Colours are the dataviz reference palette's light categorical slots in fixed order; text uses the text tokens, never
the series colour. Each chart is a self-contained SVG with its own light surface so it reads the same in a light or
dark Markdown preview.
"""

import math

SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
SURFACE = "#fcfcfb"
TEXT = "#0b0b0b"
TEXT2 = "#52514e"
GRID = "#e4e3df"
AXIS = "#b9b8b2"
FONT = "font-family='system-ui, -apple-system, Segoe UI, sans-serif'"


def _esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("'", "&#39;").replace('"', "&quot;")


def nice_ticks(lo, hi, count=5):
    """Round tick values covering [lo, hi]."""
    if hi <= lo:
        hi = lo + 1
    span = hi - lo
    raw = span / count
    mag = 10 ** math.floor(math.log10(raw))
    step = min((m * mag for m in (1, 2, 2.5, 5, 10) if m * mag >= raw), default=10 * mag)
    start = math.floor(lo / step) * step
    ticks = []
    v = start
    while v <= hi + step * 0.001:
        ticks.append(round(v, 10))
        v += step
    if ticks[-1] < hi:
        ticks.append(ticks[-1] + step)
    return ticks


def _fmt(v):
    if abs(v) >= 1000:
        return f"{v:,.0f}"
    if v == int(v):
        return str(int(v))
    return f"{v:g}"


class _Frame:
    def __init__(self, title, subtitle, width, height, xlabel, ylabel):
        self.w, self.h = width, height
        self.left, self.right, self.top, self.bottom = 64, 24, 86 if subtitle else 66, 52
        self.parts = [
            f"<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{height}' viewBox='0 0 {width} {height}' "
            f"role='img' aria-label='{_esc(title)}'>",
            f"<rect width='{width}' height='{height}' rx='8' fill='{SURFACE}'/>",
            f"<text x='16' y='26' {FONT} font-size='15' font-weight='600' fill='{TEXT}'>{_esc(title)}</text>",
        ]
        if subtitle:
            self.parts.append(f"<text x='16' y='45' {FONT} font-size='12' fill='{TEXT2}'>{_esc(subtitle)}</text>")
        self.xlabel, self.ylabel = xlabel, ylabel

    @property
    def pw(self):
        return self.w - self.left - self.right

    @property
    def ph(self):
        return self.h - self.top - self.bottom

    def yaxis(self, ticks, fy):
        for t in ticks:
            y = fy(t)
            self.parts.append(f"<line x1='{self.left}' x2='{self.w - self.right}' y1='{y:.1f}' y2='{y:.1f}' stroke='{GRID}' stroke-width='1'/>")
            self.parts.append(f"<text x='{self.left - 8}' y='{y + 4:.1f}' {FONT} font-size='11' fill='{TEXT2}' text-anchor='end'>{_fmt(t)}</text>")
        if self.ylabel:
            cx, cy = 14, self.top + self.ph / 2
            self.parts.append(f"<text x='{cx}' y='{cy}' {FONT} font-size='11' fill='{TEXT2}' text-anchor='middle' transform='rotate(-90 {cx} {cy})'>{_esc(self.ylabel)}</text>")
        if self.xlabel:
            self.parts.append(f"<text x='{self.left + self.pw / 2}' y='{self.h - 10}' {FONT} font-size='11' fill='{TEXT2}' text-anchor='middle'>{_esc(self.xlabel)}</text>")
        base = self.top + self.ph
        self.parts.append(f"<line x1='{self.left}' x2='{self.w - self.right}' y1='{base}' y2='{base}' stroke='{AXIS}' stroke-width='1'/>")

    def legend(self, names, dashed=()):
        x = self.left
        y = self.top - 20
        for i, name in enumerate(names):
            color = SERIES[i % len(SERIES)]
            dash = " stroke-dasharray='5 3'" if i in dashed else ""
            self.parts.append(f"<line x1='{x}' x2='{x + 16}' y1='{y}' y2='{y}' stroke='{color}' stroke-width='3'{dash}/>")
            self.parts.append(f"<text x='{x + 21}' y='{y + 4}' {FONT} font-size='11' fill='{TEXT}'>{_esc(name)}</text>")
            x += 21 + 6.6 * len(name) + 18

    def done(self):
        self.parts.append("</svg>")
        return "\n".join(self.parts)


def line_chart(path, title, series, xlabel="", ylabel="", subtitle="", width=760, height=340, ymin=0.0, ymax=None,
               xmax=None, refs=(), dashed=()):
    """series: list of (name, [(x, y), ...]). refs: list of (label, y) horizontal reference lines."""
    f = _Frame(title, subtitle, width, height, xlabel, ylabel)
    xs = [x for _, pts in series for x, _ in pts]
    ys = [y for _, pts in series for _, y in pts] + [y for _, y in refs]
    x0, x1 = min(xs), xmax if xmax is not None else max(xs)
    hi = ymax if ymax is not None else max(ys) * 1.08
    ticks = nice_ticks(ymin, hi)
    top = ticks[-1]
    fx = lambda x: f.left + (x - x0) / (x1 - x0 or 1) * f.pw
    fy = lambda y: f.top + f.ph - (min(y, top) - ymin) / (top - ymin) * f.ph
    f.yaxis(ticks, fy)
    for t in nice_ticks(x0, x1, 8):
        if x0 <= t <= x1:
            f.parts.append(f"<text x='{fx(t):.1f}' y='{f.top + f.ph + 16}' {FONT} font-size='11' fill='{TEXT2}' text-anchor='middle'>{_fmt(t)}</text>")
    for label, y in refs:
        f.parts.append(f"<line x1='{f.left}' x2='{f.w - f.right}' y1='{fy(y):.1f}' y2='{fy(y):.1f}' stroke='{TEXT2}' stroke-width='1.5' stroke-dasharray='6 4'/>")
        f.parts.append(f"<text x='{f.w - f.right - 4}' y='{fy(y) - 5:.1f}' {FONT} font-size='11' fill='{TEXT2}' text-anchor='end'>{_esc(label)}</text>")
    for i, (name, pts) in enumerate(series):
        color = SERIES[i % len(SERIES)]
        dash = " stroke-dasharray='5 3'" if i in dashed else ""
        d = " ".join(f"{'M' if j == 0 else 'L'}{fx(x):.1f},{fy(y):.1f}" for j, (x, y) in enumerate(pts) if x <= x1)
        f.parts.append(f"<path d='{d}' fill='none' stroke='{color}' stroke-width='2' stroke-linejoin='round'{dash}><title>{_esc(name)}</title></path>")
    f.legend([n for n, _ in series], dashed)
    with open(path, "w", encoding="utf-8") as out:
        out.write(f.done())


def bar_chart(path, title, categories, series, xlabel="", ylabel="", subtitle="", width=760, height=340, refs=(),
              labels=True):
    """categories: x labels; series: list of (name, [value per category])."""
    f = _Frame(title, subtitle, width, height, xlabel, ylabel)
    hi = max([v for _, vals in series for v in vals if v is not None] + [y for _, y in refs]) * 1.12
    ticks = nice_ticks(0, hi)
    top = ticks[-1]
    fy = lambda y: f.top + f.ph - y / top * f.ph
    f.yaxis(ticks, fy)
    n = len(series)
    group = f.pw / len(categories)
    bar = min(28.0, (group * 0.7 - 2 * (n - 1)) / n)
    for ci, cat in enumerate(categories):
        gx = f.left + ci * group + (group - (n * bar + 2 * (n - 1))) / 2
        for si, (name, vals) in enumerate(series):
            v = vals[ci]
            if v is None:
                continue
            x = gx + si * (bar + 2)
            y = fy(v)
            h = f.top + f.ph - y
            r = min(4.0, bar / 2, h)
            color = SERIES[si % len(SERIES)]
            # Rounded data end, square at the baseline.
            f.parts.append(
                f"<path d='M{x:.1f},{f.top + f.ph:.1f} V{y + r:.1f} Q{x:.1f},{y:.1f} {x + r:.1f},{y:.1f} H{x + bar - r:.1f} "
                f"Q{x + bar:.1f},{y:.1f} {x + bar:.1f},{y + r:.1f} V{f.top + f.ph:.1f} Z' fill='{color}'><title>{_esc(name)}, {_esc(cat)}: {_fmt(v)}</title></path>")
            if labels:
                f.parts.append(f"<text x='{x + bar / 2:.1f}' y='{y - 4:.1f}' {FONT} font-size='10' fill='{TEXT2}' text-anchor='middle'>{_fmt(round(v))}</text>")
        f.parts.append(f"<text x='{f.left + ci * group + group / 2:.1f}' y='{f.top + f.ph + 16}' {FONT} font-size='11' fill='{TEXT2}' text-anchor='middle'>{_esc(cat)}</text>")
    for label, y in refs:
        f.parts.append(f"<line x1='{f.left}' x2='{f.w - f.right}' y1='{fy(y):.1f}' y2='{fy(y):.1f}' stroke='{TEXT2}' stroke-width='1.5' stroke-dasharray='6 4'/>")
        f.parts.append(f"<text x='{f.w - f.right - 4}' y='{fy(y) - 5:.1f}' {FONT} font-size='11' fill='{TEXT2}' text-anchor='end'>{_esc(label)}</text>")
    if n > 1:
        f.legend([nm for nm, _ in series])
    with open(path, "w", encoding="utf-8") as out:
        out.write(f.done())
