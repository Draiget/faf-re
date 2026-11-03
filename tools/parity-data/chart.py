"""The README's and docs/RETAIL_REPLAY_PARITY.md's parity charts, as SVG, from a full run's report.

    python tools/parity-data/chart.py --report <report dir>/report.json

Download the report with: gh run download <run id> -R Draiget/faf-re -n report -D <report dir>.
The report has each replay's verdict, players and length. Why a replay desynced is worked out by
hand, so the causes come from parity_chart.json; update that file with the run. Each chart is
written twice, for GitHub's light and dark themes (a <picture> in the Markdown picks one).
"""
import argparse
import json
import os
from xml.sax.saxutils import escape

HERE = os.path.dirname(os.path.abspath(__file__))
PLAYED = ("pass", "desync", "timeout", "crash")
# A replay the cancelled run never reached has this error; the other errors did try to play.
NOT_REACHED = "no result from shard"

THEMES = {
    "light": {
        "ink": "#1f2328", "muted": "#59636e", "grid": "#d1d9e0", "wash": "#1f2328", "pass": "#1a7f37",
        "runner": "#6e7681", "desync": "#6250d6", "blue": "#2a78d6", "orange": "#eb6834",
        "aqua": "#1baf7a", "yellow": "#eda100",
    },
    "dark": {
        "ink": "#e6edf3", "muted": "#9198a1", "grid": "#3d444d", "wash": "#e6edf3", "pass": "#238636",
        "runner": "#6e7681", "desync": "#9085e9", "blue": "#3987e5", "orange": "#d95926",
        "aqua": "#199e70", "yellow": "#c98500",
    },
}


class Svg:
    def __init__(self, width, height, title, desc):
        self.parts = [
            '<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" '
            'font-family="system-ui, -apple-system, \'Segoe UI\', Helvetica, Arial, sans-serif">' % (width, height, width, height),
            "<title>%s</title>" % escape(title),
            "<desc>%s</desc>" % escape(desc),
        ]

    def text(self, x, y, value, fill, size=13, weight=None, anchor=None):
        extra = (' font-weight="%s"' % weight if weight else "") + (' text-anchor="%s"' % anchor if anchor else "")
        self.parts.append('<text x="%.1f" y="%.1f" font-size="%d" fill="%s"%s>%s</text>' % (x, y, size, fill, extra, escape(value)))

    def rect(self, x, y, width, height, fill, radius=4):
        self.parts.append('<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" rx="%.2f" fill="%s"/>' % (
            x, y, width, height, min(radius, width / 2), fill))

    def bar_end(self, x, y, width, height, fill, radius=4):
        """A bar segment rounded at its data end only, square at the baseline."""
        radius = min(radius, width)
        self.parts.append('<path d="M%.2f %.2fh%.2fq%.2f 0 %.2f %.2fv%.2fq0 %.2f %.2f %.2fh%.2fz" fill="%s"/>' % (
            x, y, width - radius, radius, radius, radius, height - 2 * radius, radius, -radius, radius,
            -(width - radius), fill))

    def line(self, x1, y1, x2, y2, stroke):
        self.parts.append('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s"/>' % (x1, y1, x2, y2, stroke))

    def polygon(self, points, fill, opacity):
        self.parts.append('<polygon points="%s" fill="%s" fill-opacity="%s"/>' % (
            " ".join("%.1f,%.1f" % p for p in points), fill, opacity))

    def write(self, path):
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(self.parts + ["</svg>", ""]))


def percent(count, total, digits=2):
    return "%.*f %%" % (digits, 100.0 * count / total)


def segments(svg, x, width, y, height, parts, gap=2):
    """One whole split into blocks. parts: (count, fill, label). Returns each block's (x, width)."""
    total = sum(p[0] for p in parts)
    usable = width - gap * (len(parts) - 1)
    spans = []
    for count, fill, label in parts:
        block = usable * count / total
        svg.rect(x, y, block, height, fill)
        if label and len(label) * 8 + 16 < block:
            svg.text(x + 8, y + height / 2 + 5, label, "#ffffff", 14, "600")
        spans.append((x, block))
        x += block + gap
    return spans


def overview(path, theme, data, counts):
    """All played replays, and below them, zoomed, the ones that did not pass."""
    t = THEMES[theme]
    width, passed, played, desync = 880, counts["pass"], counts["played"], counts["desync"]
    failed, runner = played - passed, played - passed - desync
    title = "%s of %s vault replays match every recorded checksum (%s)" % (
        format(passed, ","), format(played, ","), percent(passed, played))
    desc = "%s did not pass: %s, and %s CI runner failures." % (format(failed, ","), ", ".join(
        "%s: %d" % (c["label"], c["count"]) for c in data["desync_causes"]), format(runner, ","))
    svg = Svg(width, 286, title, desc)
    svg.text(0, 20, title, t["ink"], 18, "600")
    svg.text(0, 42, "CI run %s, commit %s, %s, %s. Causes as of %s." % (
        data["run"], data["commit"], data["build"], data["dates"], data["causes_as_of"]), t["muted"])

    top, bottom, height = 58, 128, 28
    spans = segments(svg, 0, width, top, height, [
        (passed, t["pass"], "Pass: %s (%s)" % (format(passed, ","), percent(passed, played))),
        (failed, t["ink"], None)])
    x, block = spans[1]
    svg.polygon([(x, top + height + 1), (x + block, top + height + 1), (width, bottom - 2), (0, bottom - 2)], t["wash"], "0.08")
    svg.text(0, top + height + 21, "The %s that did not pass (%s)" % (format(failed, ","), percent(failed, played)), t["ink"], 13, "600")

    causes = data["desync_causes"]
    parts = [(c["count"], t[c["color"]], str(c["count"])) for c in causes] + [(runner, t["runner"], str(runner))]
    spans = segments(svg, 0, width, bottom, height, parts)

    # What each group of blocks adds up to.
    y = bottom + height + 8
    groups = (
        (spans[0][0], spans[len(causes) - 1][0] + spans[len(causes) - 1][1], "%d desyncs (%s)" % (desync, percent(desync, played))),
        (spans[-1][0], width, "%d CI runner failures (%s)" % (runner, percent(runner, played))))
    for start, end, label in groups:
        svg.line(start + 1, y, end - 1, y, t["grid"])
        svg.line(start + 1, y - 4, start + 1, y, t["grid"])
        svg.line(end - 1, y - 4, end - 1, y, t["grid"])
        svg.text((start + end) / 2, y + 17, label, t["ink"], 13, "600", "middle")

    y += 40
    legend = [("%s: %d" % (c["label"], c["count"]), t[c["color"]]) for c in causes]
    legend.append(("CI runner: %d timeouts, %d map extraction crashes, %d maps not on FAF's server" % (
        counts["timeout"], counts["crash"], counts["error"]), t["runner"]))
    for label, fill in legend:
        svg.rect(0, y - 10, 11, 11, fill, 2)
        svg.text(18, y, label, t["muted"])
        y += 19
    svg.write(path)


def not_passed_panel(svg, t, x0, y0, title, rows):
    """rows: (label, desync, runner, total). Every bar is labeled, so only the baseline is drawn;
    bars share one scale, 200 px for 10 % of a row's replays."""
    label_w, bar_w, top = 104, 200, y0 + 24
    pitch = 25
    svg.text(x0, y0, title, t["ink"], 14, "600")
    svg.text(x0 + 420, y0, "Replays", t["muted"], 12, None, "end")
    bottom = top + pitch * len(rows)
    svg.line(x0 + label_w, top - 6, x0 + label_w, bottom - 6, t["grid"])
    for i, (label, desync, runner, total) in enumerate(rows):
        y = top + pitch * i
        svg.text(x0, y + 10, label, t["ink"])
        x = x0 + label_w
        desync_w, runner_w = bar_w * (100.0 * desync / total) / 10, bar_w * (100.0 * runner / total) / 10
        if desync and runner:
            svg.rect(x, y, desync_w, 13, t["desync"], 0)
            svg.bar_end(x + desync_w + 2, y, max(runner_w, 1), 13, t["runner"])
        elif desync:
            svg.bar_end(x, y, desync_w, 13, t["desync"])
        elif runner:
            svg.bar_end(x, y, runner_w, 13, t["runner"])
        tip = x + desync_w + runner_w + (6 if desync and runner else 4)
        svg.text(tip, y + 10, percent(desync + runner, total, 1), t["ink"], 12, "600")
        svg.text(x0 + 420, y + 10, format(total, ","), t["muted"], 12, None, "end")
    return bottom


def breakdown(path, theme, data, players, lengths, skipped):
    t = THEMES[theme]
    title = "Replays that did not pass, by player count and game length"
    desc = "; ".join("%s: %s of %d" % (r[0], percent(r[1] + r[2], r[3], 1), r[3]) for r in players + lengths)
    svg = Svg(880, 318, title, desc)  # room for 7 rows in each panel and the note under them
    svg.text(0, 20, title, t["ink"], 18, "600")
    svg.text(0, 42, "CI run %s, commit %s, before the fixes. Share of each row's replays." % (data["run"], data["commit"]), t["muted"])
    svg.rect(0, 56, 11, 11, t["desync"], 2)
    svg.text(18, 66, "Desync", t["muted"])
    svg.rect(84, 56, 11, 11, t["runner"], 2)
    svg.text(102, 66, "CI runner failure", t["muted"])
    bottom = max(not_passed_panel(svg, t, 0, 96, "By player count", players), not_passed_panel(svg, t, 460, 96, "By game length", lengths))
    svg.text(0, bottom + 14, skipped, t["muted"], 12)
    svg.write(path)


def player_group(players):
    if players <= 4 or players == 8:
        return "%d players" % players
    if players <= 7:
        return "5–7 players"
    return "9–11 players" if players <= 11 else "12+ players"


def length_group(ticks):
    minutes = ticks / 600.0  # the sim runs 10 ticks per game second
    for low, high in ((0, 10), (10, 20), (20, 30), (30, 45), (45, 60), (60, 90)):
        if minutes < high:
            return "Under 10 min" if low == 0 else "%d–%d min" % (low, high)
    return "90 min or more"


def rows_by(replays, key, order):
    rows = {name: [name, 0, 0, 0] for name in order}
    for r in replays:
        row = rows[key(r)]
        row[1] += r["verdict"] == "desync"
        row[2] += r["verdict"] in ("timeout", "crash")
        row[3] += 1
    return [tuple(rows[name]) for name in order]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--report", required=True, help="report.json of a Replay parity run")
    parser.add_argument("--data", default=os.path.join(HERE, "parity_chart.json"))
    parser.add_argument("--out", default=os.path.join(HERE, "..", "..", "docs", "images"))
    args = parser.parse_args()

    with open(args.report, encoding="utf-8") as f:
        replays = json.load(f)["replays"]
    with open(args.data, encoding="utf-8") as f:
        data = json.load(f)

    played = [r for r in replays if r["verdict"] in PLAYED]
    errors = [r for r in replays if r["verdict"] == "error" and not str(r.get("why", "")).startswith(NOT_REACHED)]
    counts = {v: sum(r["verdict"] == v for r in played) for v in PLAYED}
    counts["error"] = len(errors)
    counts["played"] = len(played) + len(errors)

    listed = sum(c["count"] for c in data["desync_causes"])
    if listed != counts["desync"]:
        raise SystemExit("parity_chart.json lists %d desyncs, the report has %d" % (listed, counts["desync"]))

    with_length = [r for r in played if r.get("length")]
    players = rows_by(played, lambda r: player_group(r["players"]), [
        "2 players", "3 players", "4 players", "5–7 players", "8 players", "9–11 players", "12+ players"])
    lengths = rows_by(with_length, lambda r: length_group(r["length"]), [
        "Under 10 min", "10–20 min", "20–30 min", "30–45 min", "45–60 min", "60–90 min", "90 min or more"])
    skipped = "Not shown: %d replays whose map was missing, so they never loaded. The game length rows also leave out %d with no recorded length." % (
        len(errors), len(played) - len(with_length))

    os.makedirs(args.out, exist_ok=True)
    for theme in THEMES:
        overview(os.path.join(args.out, "parity-overview-%s.svg" % theme), theme, data, counts)
        breakdown(os.path.join(args.out, "parity-breakdown-%s.svg" % theme), theme, data, players, lengths, skipped)
    print(counts)
    for row in players + lengths:
        print("%-16s desync %4d  runner %4d  of %5d  not passed %s" % (row[0], row[1], row[2], row[3], percent(row[1] + row[2], row[3], 1)))


if __name__ == "__main__":
    main()
