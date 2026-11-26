#include "moho/ui/UiArt.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <limits>
#include <map>
#include <mutex>
#include <numbers>

#include <zlib.h>

namespace moho::uiart
{
  namespace
  {
    struct Point
    {
      double x = 0.0;
      double y = 0.0;
    };

    /** One run of connected points; `closed` joins the last back to the first. */
    struct Line
    {
      std::vector<Point> points;
      bool closed = false;
    };

    struct Drawing
    {
      std::vector<Line> strokes;
      std::vector<Line> fills;
    };

    constexpr double kPi = std::numbers::pi;

    bool IsSeparator(
      const char c
    )
    {
      return c == ' ' || c == ',' || c == '\t' || c == '\n' || c == '\r';
    }

    void SkipSeparators(
      const std::string_view text,
      std::size_t& at
    )
    {
      while (at < text.size() && IsSeparator(text[at])) {
        ++at;
      }
    }

    /** A number in SVG's syntax ("-1.5", ".5", "1e-3", and "0.5.5" as two), without the C locale's help. */
    bool ReadNumber(
      const std::string_view text,
      std::size_t& at,
      double& out
    )
    {
      SkipSeparators(text, at);
      std::size_t i = at;
      double sign = 1.0;
      if (i < text.size() && (text[i] == '-' || text[i] == '+')) {
        sign = text[i] == '-' ? -1.0 : 1.0;
        ++i;
      }
      double value = 0.0;
      bool digits = false;
      while (i < text.size() && std::isdigit(static_cast<unsigned char>(text[i]))) {
        value = value * 10.0 + (text[i] - '0');
        digits = true;
        ++i;
      }
      if (i < text.size() && text[i] == '.') {
        ++i;
        double scale = 0.1;
        while (i < text.size() && std::isdigit(static_cast<unsigned char>(text[i]))) {
          value += (text[i] - '0') * scale;
          scale *= 0.1;
          digits = true;
          ++i;
        }
      }
      if (!digits) {
        return false;
      }
      if (i < text.size() && (text[i] == 'e' || text[i] == 'E')) {
        std::size_t e = i + 1;
        int expSign = 1;
        if (e < text.size() && (text[e] == '-' || text[e] == '+')) {
          expSign = text[e] == '-' ? -1 : 1;
          ++e;
        }
        int exponent = 0;
        bool expDigits = false;
        while (e < text.size() && std::isdigit(static_cast<unsigned char>(text[e]))) {
          exponent = exponent * 10 + (text[e] - '0');
          expDigits = true;
          ++e;
        }
        if (expDigits) {
          value *= std::pow(10.0, expSign * exponent);
          i = e;
        }
      }
      out = sign * value;
      at = i;
      return true;
    }

    /** An arc's flag: one character, '0' or '1', which may touch the next number ("a1 1 0 01.5 2"). */
    bool ReadFlag(
      const std::string_view text,
      std::size_t& at,
      bool& out
    )
    {
      SkipSeparators(text, at);
      if (at < text.size() && (text[at] == '0' || text[at] == '1')) {
        out = text[at] == '1';
        ++at;
        return true;
      }
      return false;
    }

    void AddCubic(
      std::vector<Point>& points,
      const Point p0,
      const Point p1,
      const Point p2,
      const Point p3
    )
    {
      constexpr int kSteps = 24;
      for (int k = 1; k <= kSteps; ++k) {
        const double t = static_cast<double>(k) / kSteps;
        const double u = 1.0 - t;
        points.push_back({
          u * u * u * p0.x + 3 * u * u * t * p1.x + 3 * u * t * t * p2.x + t * t * t * p3.x,
          u * u * u * p0.y + 3 * u * u * t * p1.y + 3 * u * t * t * p2.y + t * t * t * p3.y,
        });
      }
    }

    void AddQuadratic(
      std::vector<Point>& points,
      const Point p0,
      const Point p1,
      const Point p2
    )
    {
      constexpr int kSteps = 20;
      for (int k = 1; k <= kSteps; ++k) {
        const double t = static_cast<double>(k) / kSteps;
        const double u = 1.0 - t;
        points.push_back({
          u * u * p0.x + 2 * u * t * p1.x + t * t * p2.x,
          u * u * p0.y + 2 * u * t * p1.y + t * t * p2.y,
        });
      }
    }

    double Angle(
      const double ux,
      const double uy,
      const double vx,
      const double vy
    )
    {
      return std::atan2(ux * vy - uy * vx, ux * vx + uy * vy);
    }

    /** SVG's elliptical arc from `from` to `to` (the endpoint form, SVG 1.1 implementation notes F.6.5). */
    void AddArc(
      std::vector<Point>& points,
      const Point from,
      double rx,
      double ry,
      const double rotationDegrees,
      const bool large,
      const bool sweep,
      const Point to
    )
    {
      rx = std::abs(rx);
      ry = std::abs(ry);
      if (rx < 1e-9 || ry < 1e-9 || (from.x == to.x && from.y == to.y)) {
        points.push_back(to);
        return;
      }
      const double phi = rotationDegrees * kPi / 180.0;
      const double cosPhi = std::cos(phi);
      const double sinPhi = std::sin(phi);
      const double dx2 = (from.x - to.x) / 2.0;
      const double dy2 = (from.y - to.y) / 2.0;
      const double x1 = cosPhi * dx2 + sinPhi * dy2;
      const double y1 = -sinPhi * dx2 + cosPhi * dy2;
      if (const double lambda = (x1 * x1) / (rx * rx) + (y1 * y1) / (ry * ry); lambda > 1.0) {
        rx *= std::sqrt(lambda);
        ry *= std::sqrt(lambda);
      }
      const double numerator = rx * rx * ry * ry - rx * rx * y1 * y1 - ry * ry * x1 * x1;
      const double denominator = rx * rx * y1 * y1 + ry * ry * x1 * x1;
      double coefficient = denominator > 0.0 ? std::sqrt(std::max(0.0, numerator / denominator)) : 0.0;
      if (large == sweep) {
        coefficient = -coefficient;
      }
      const double cx1 = coefficient * rx * y1 / ry;
      const double cy1 = -coefficient * ry * x1 / rx;
      const double cx = cosPhi * cx1 - sinPhi * cy1 + (from.x + to.x) / 2.0;
      const double cy = sinPhi * cx1 + cosPhi * cy1 + (from.y + to.y) / 2.0;
      const double theta = Angle(1.0, 0.0, (x1 - cx1) / rx, (y1 - cy1) / ry);
      double delta = Angle((x1 - cx1) / rx, (y1 - cy1) / ry, (-x1 - cx1) / rx, (-y1 - cy1) / ry);
      if (!sweep && delta > 0) {
        delta -= 2 * kPi;
      } else if (sweep && delta < 0) {
        delta += 2 * kPi;
      }
      const int steps = std::max(4, static_cast<int>(std::ceil(std::abs(delta) / (kPi / 24.0))));
      for (int k = 1; k <= steps; ++k) {
        const double t = theta + delta * k / steps;
        points.push_back({
          cx + rx * std::cos(t) * cosPhi - ry * std::sin(t) * sinPhi,
          cy + rx * std::cos(t) * sinPhi + ry * std::sin(t) * cosPhi,
        });
      }
      points.back() = to;
    }

    /** SVG path data into runs of points. */
    std::expected<std::vector<Line>, std::string> ParsePath(
      const std::string_view d
    )
    {
      std::vector<Line> lines;
      Line current;
      Point point;
      Point start;
      Point lastCubic; // the last control point of a C or S, for S's reflection
      Point lastQuad;  // of a Q or T, for T's
      char previous = 0;
      char command = 0;
      const auto flush = [&] {
        if (current.points.size() >= 2) {
          lines.push_back(std::move(current));
        }
        current = Line{};
      };
      std::size_t at = 0;
      for (;;) {
        SkipSeparators(d, at);
        if (at >= d.size()) {
          break;
        }
        if (std::isalpha(static_cast<unsigned char>(d[at]))) {
          command = d[at++];
        } else if (command == 0) {
          return std::unexpected("path data starts without a command");
        }
        const bool relative = std::islower(static_cast<unsigned char>(command)) != 0;
        const char kind = static_cast<char>(std::tolower(static_cast<unsigned char>(command)));
        const auto read = [&](double& value) {
          return ReadNumber(d, at, value);
        };
        const auto readPoint = [&](Point& p) {
          if (!read(p.x) || !read(p.y)) {
            return false;
          }
          if (relative) {
            p.x += point.x;
            p.y += point.y;
          }
          return true;
        };
        if (kind == 'z') {
          if (!current.points.empty()) {
            current.closed = true;
            flush();
          }
          point = start;
          previous = 'z';
          command = 0; // a number after Z is an error, as SVG has it
          continue;
        }
        if (current.points.empty() && kind != 'm') {
          current.points.push_back(point); // drawing on after Z starts at the subpath's start
        }
        switch (kind) {
        case 'm': {
          Point p;
          if (!readPoint(p)) {
            return std::unexpected("bad M");
          }
          flush();
          current.points.push_back(p);
          point = start = p;
          command = relative ? 'l' : 'L'; // further pairs are lines
          break;
        }
        case 'l': {
          Point p;
          if (!readPoint(p)) {
            return std::unexpected("bad L");
          }
          current.points.push_back(p);
          point = p;
          break;
        }
        case 'h': {
          double x = 0;
          if (!read(x)) {
            return std::unexpected("bad H");
          }
          point.x = relative ? point.x + x : x;
          current.points.push_back(point);
          break;
        }
        case 'v': {
          double y = 0;
          if (!read(y)) {
            return std::unexpected("bad V");
          }
          point.y = relative ? point.y + y : y;
          current.points.push_back(point);
          break;
        }
        case 'c': {
          Point c1;
          Point c2;
          Point p;
          if (!readPoint(c1) || !readPoint(c2) || !readPoint(p)) {
            return std::unexpected("bad C");
          }
          AddCubic(current.points, point, c1, c2, p);
          lastCubic = c2;
          point = p;
          break;
        }
        case 's': {
          const Point c1 =
            (previous == 'c' || previous == 's') ? Point{2 * point.x - lastCubic.x, 2 * point.y - lastCubic.y} : point;
          Point c2;
          Point p;
          if (!readPoint(c2) || !readPoint(p)) {
            return std::unexpected("bad S");
          }
          AddCubic(current.points, point, c1, c2, p);
          lastCubic = c2;
          point = p;
          break;
        }
        case 'q': {
          Point c;
          Point p;
          if (!readPoint(c) || !readPoint(p)) {
            return std::unexpected("bad Q");
          }
          AddQuadratic(current.points, point, c, p);
          lastQuad = c;
          point = p;
          break;
        }
        case 't': {
          const Point c =
            (previous == 'q' || previous == 't') ? Point{2 * point.x - lastQuad.x, 2 * point.y - lastQuad.y} : point;
          Point p;
          if (!readPoint(p)) {
            return std::unexpected("bad T");
          }
          AddQuadratic(current.points, point, c, p);
          lastQuad = c;
          point = p;
          break;
        }
        case 'a': {
          double rx = 0;
          double ry = 0;
          double rotation = 0;
          bool large = false;
          bool sweep = false;
          Point p;
          if (
            !read(rx) || !read(ry) || !read(rotation) || !ReadFlag(d, at, large) || !ReadFlag(d, at, sweep) ||
            !readPoint(p)
          ) {
            return std::unexpected("bad A");
          }
          AddArc(current.points, point, rx, ry, rotation, large, sweep, p);
          point = p;
          break;
        }
        default:
          return std::unexpected(std::string("unknown path command ") + command);
        }
        previous = kind;
      }
      flush();
      return lines;
    }

    std::vector<Point> Ellipse(
      const double cx,
      const double cy,
      const double rx,
      const double ry
    )
    {
      constexpr int kSteps = 72;
      std::vector<Point> points;
      for (int k = 0; k < kSteps; ++k) {
        const double t = 2 * kPi * k / kSteps;
        points.push_back({cx + rx * std::cos(t), cy + ry * std::sin(t)});
      }
      return points;
    }

    std::vector<Point> RoundedRectangle(
      const double x,
      const double y,
      const double w,
      const double h,
      double rx,
      double ry
    )
    {
      rx = std::clamp(rx, 0.0, w / 2);
      ry = std::clamp(ry, 0.0, h / 2);
      std::vector<Point> points;
      if (rx <= 0 || ry <= 0) {
        return {{x, y}, {x + w, y}, {x + w, y + h}, {x, y + h}};
      }
      constexpr int kSteps = 12;
      const auto corner = [&](const double cx, const double cy, const double from) {
        for (int k = 0; k <= kSteps; ++k) {
          const double t = from + (kPi / 2) * k / kSteps;
          points.push_back({cx + rx * std::cos(t), cy + ry * std::sin(t)});
        }
      };
      corner(x + w - rx, y + ry, -kPi / 2);
      corner(x + w - rx, y + h - ry, 0);
      corner(x + rx, y + h - ry, kPi / 2);
      corner(x + rx, y + ry, kPi);
      return points;
    }

    std::vector<Point> PointList(
      const std::string_view text
    )
    {
      std::vector<Point> points;
      std::size_t at = 0;
      Point p;
      while (ReadNumber(text, at, p.x) && ReadNumber(text, at, p.y)) {
        points.push_back(p);
      }
      return points;
    }

    /** Each element's tag and attributes, from text such as `<path d="..." /><circle cx="12" ... />`. */
    std::expected<Drawing, std::string> ParseElements(
      const std::string_view text
    )
    {
      Drawing drawing;
      std::size_t at = 0;
      while ((at = text.find('<', at)) != std::string_view::npos) {
        ++at;
        if (at < text.size() && (text[at] == '/' || text[at] == '!' || text[at] == '?')) {
          at = text.find('>', at);
          if (at == std::string_view::npos) {
            break;
          }
          continue;
        }
        std::size_t nameEnd = at;
        while (nameEnd < text.size() &&
               (std::isalnum(static_cast<unsigned char>(text[nameEnd])) || text[nameEnd] == '-')) {
          ++nameEnd;
        }
        const std::string tag(text.substr(at, nameEnd - at));
        std::map<std::string, std::string> attributes;
        at = nameEnd;
        for (;;) {
          while (at < text.size() && (IsSeparator(text[at]) || text[at] == '/')) {
            ++at;
          }
          if (at >= text.size() || text[at] == '>') {
            break;
          }
          std::size_t keyEnd = at;
          while (keyEnd < text.size() && text[keyEnd] != '=' && text[keyEnd] != '>' && !IsSeparator(text[keyEnd])) {
            ++keyEnd;
          }
          const std::string key(text.substr(at, keyEnd - at));
          at = keyEnd;
          if (at < text.size() && text[at] == '=') {
            ++at;
            const char quote = at < text.size() ? text[at] : '\0';
            if (quote == '"' || quote == '\'') {
              const std::size_t close = text.find(quote, at + 1);
              if (close == std::string_view::npos) {
                return std::unexpected("an attribute isn't closed: " + key);
              }
              attributes[key] = std::string(text.substr(at + 1, close - at - 1));
              at = close + 1;
            }
          }
        }
        const auto number = [&attributes](const char* key, const double fallback = 0.0) {
          const auto found = attributes.find(key);
          if (found == attributes.end()) {
            return fallback;
          }
          double value = fallback;
          std::size_t i = 0;
          return ReadNumber(found->second, i, value) ? value : fallback;
        };
        const auto fill = attributes.find("fill");
        const bool filled = fill != attributes.end() && fill->second != "none";
        const auto stroke = attributes.find("stroke");
        const bool stroked = stroke == attributes.end() || stroke->second != "none";
        std::vector<Line> lines;
        if (tag == "path") {
          auto parsed = ParsePath(attributes["d"]);
          if (!parsed) {
            return std::unexpected(parsed.error());
          }
          lines = std::move(*parsed);
        } else if (tag == "circle") {
          lines.push_back({Ellipse(number("cx"), number("cy"), number("r"), number("r")), true});
        } else if (tag == "ellipse") {
          lines.push_back({Ellipse(number("cx"), number("cy"), number("rx"), number("ry")), true});
        } else if (tag == "rect") {
          const double rx = number("rx", number("ry"));
          const double ry = number("ry", rx);
          lines.push_back(
            {RoundedRectangle(number("x"), number("y"), number("width"), number("height"), rx, ry), true}
          );
        } else if (tag == "line") {
          lines.push_back({{{number("x1"), number("y1")}, {number("x2"), number("y2")}}, false});
        } else if (tag == "polyline" || tag == "polygon") {
          lines.push_back({PointList(attributes["points"]), tag == "polygon"});
        } else {
          continue; // svg, g and anything else: their children are read on their own
        }
        for (Line& line : lines) {
          if (filled) {
            drawing.fills.push_back(line);
          }
          if (stroked) {
            drawing.strokes.push_back(std::move(line));
          }
        }
      }
      return drawing;
    }

    double SegmentDistance(
      const double px,
      const double py,
      const Point a,
      const Point b
    )
    {
      const double dx = b.x - a.x;
      const double dy = b.y - a.y;
      const double length2 = dx * dx + dy * dy;
      double t = length2 > 0 ? ((px - a.x) * dx + (py - a.y) * dy) / length2 : 0.0;
      t = std::clamp(t, 0.0, 1.0);
      const double ex = a.x + t * dx - px;
      const double ey = a.y + t * dy - py;
      return std::sqrt(ex * ex + ey * ey);
    }

    std::uint8_t Byte(
      const double value
    )
    {
      return static_cast<std::uint8_t>(std::clamp(std::lround(value), 0L, 255L));
    }
  } // namespace

  bool ParseColor(
    const std::string_view text,
    Rgba& out
  )
  {
    if (text.size() != 6 && text.size() != 8) {
      return false;
    }
    std::uint32_t value = 0;
    for (const char c : text) {
      const int digit = std::isdigit(static_cast<unsigned char>(c)) ? c - '0'
        : (c >= 'a' && c <= 'f')                                    ? c - 'a' + 10
        : (c >= 'A' && c <= 'F')                                    ? c - 'A' + 10
                                                                    : -1;
      if (digit < 0) {
        return false;
      }
      value = (value << 4) | static_cast<std::uint32_t>(digit);
    }
    out.a = text.size() == 8 ? static_cast<std::uint8_t>(value >> 24) : 255;
    out.r = static_cast<std::uint8_t>(value >> 16);
    out.g = static_cast<std::uint8_t>(value >> 8);
    out.b = static_cast<std::uint8_t>(value);
    return true;
  }

  std::expected<Image, std::string> DrawIcon(
    const std::string_view elements,
    const int size,
    const Rgba color,
    const float strokeWidth,
    const float viewBox
  )
  {
    if (size <= 0 || size > 1024 || viewBox <= 0.0f) {
      return std::unexpected("an icon is 1 to 1024 pixels on a positive grid");
    }
    auto drawing = ParseElements(elements);
    if (!drawing) {
      return std::unexpected(drawing.error());
    }
    const double scale = static_cast<double>(size) / viewBox;
    for (std::vector<Line>* group : {&drawing->strokes, &drawing->fills}) {
      for (Line& line : *group) {
        for (Point& p : line.points) {
          p.x *= scale;
          p.y *= scale;
        }
      }
    }
    std::vector<double> distance(static_cast<std::size_t>(size) * size, std::numeric_limits<double>::max());
    const double half = strokeWidth * scale / 2.0;
    // Each segment only reaches the pixels within its box grown by the stroke.
    const auto stroke = [&](const Point a, const Point b) {
      const int x0 = std::max(0, static_cast<int>(std::floor(std::min(a.x, b.x) - half - 1)));
      const int x1 = std::min(size - 1, static_cast<int>(std::ceil(std::max(a.x, b.x) + half + 1)));
      const int y0 = std::max(0, static_cast<int>(std::floor(std::min(a.y, b.y) - half - 1)));
      const int y1 = std::min(size - 1, static_cast<int>(std::ceil(std::max(a.y, b.y) + half + 1)));
      for (int y = y0; y <= y1; ++y) {
        for (int x = x0; x <= x1; ++x) {
          double& d = distance[static_cast<std::size_t>(y) * size + x];
          d = std::min(d, SegmentDistance(x + 0.5, y + 0.5, a, b));
        }
      }
    };
    for (const Line& line : drawing->strokes) {
      for (std::size_t i = 1; i < line.points.size(); ++i) {
        stroke(line.points[i - 1], line.points[i]);
      }
      if (line.closed && line.points.size() > 2) {
        stroke(line.points.back(), line.points.front());
      }
    }
    std::vector<double> coverage(distance.size(), 0.0);
    for (std::size_t i = 0; i < distance.size(); ++i) {
      coverage[i] = std::clamp(half + 0.5 - distance[i], 0.0, 1.0);
    }
    // Fills: 4 x 4 samples a pixel, non-zero winding over every closed run.
    if (!drawing->fills.empty()) {
      for (int y = 0; y < size; ++y) {
        for (int x = 0; x < size; ++x) {
          int inside = 0;
          for (int sy = 0; sy < 4; ++sy) {
            for (int sx = 0; sx < 4; ++sx) {
              const double px = x + (sx + 0.5) / 4.0;
              const double py = y + (sy + 0.5) / 4.0;
              int winding = 0;
              for (const Line& line : drawing->fills) {
                const std::size_t n = line.points.size();
                for (std::size_t i = 0; i < n; ++i) {
                  const Point a = line.points[i];
                  const Point b = line.points[(i + 1) % n];
                  const double side = (b.x - a.x) * (py - a.y) - (px - a.x) * (b.y - a.y);
                  if (a.y <= py) {
                    if (b.y > py && side > 0) {
                      ++winding;
                    }
                  } else if (b.y <= py && side < 0) {
                    --winding;
                  }
                }
              }
              inside += winding != 0 ? 1 : 0;
            }
          }
          double& c = coverage[static_cast<std::size_t>(y) * size + x];
          c = std::max(c, inside / 16.0);
        }
      }
    }
    Image image;
    image.width = size;
    image.height = size;
    image.rgba.resize(coverage.size() * 4);
    for (std::size_t i = 0; i < coverage.size(); ++i) {
      image.rgba[i * 4 + 0] = color.r;
      image.rgba[i * 4 + 1] = color.g;
      image.rgba[i * 4 + 2] = color.b;
      image.rgba[i * 4 + 3] = Byte(color.a * coverage[i]);
    }
    return image;
  }

  Image DrawRoundedRect(
    const int width,
    const int height,
    const float radius,
    const Rgba fill,
    const Rgba border,
    const float borderWidth
  )
  {
    Image image;
    image.width = std::max(width, 1);
    image.height = std::max(height, 1);
    image.rgba.resize(static_cast<std::size_t>(image.width) * image.height * 4);
    const double halfW = image.width / 2.0;
    const double halfH = image.height / 2.0;
    const double r = std::clamp(static_cast<double>(radius), 0.0, std::min(halfW, halfH));
    for (int y = 0; y < image.height; ++y) {
      for (int x = 0; x < image.width; ++x) {
        // The box's signed distance: negative inside, 0 on its edge.
        const double qx = std::abs(x + 0.5 - halfW) - (halfW - r);
        const double qy = std::abs(y + 0.5 - halfH) - (halfH - r);
        const double outside = std::hypot(std::max(qx, 0.0), std::max(qy, 0.0));
        const double signedDistance = outside + std::min(std::max(qx, qy), 0.0) - r;
        const double outer = std::clamp(0.5 - signedDistance, 0.0, 1.0);
        const double inner = borderWidth > 0.0f ? std::clamp(0.5 - (signedDistance + borderWidth), 0.0, 1.0) : outer;
        const double fillAlpha = fill.a / 255.0 * inner;
        const double borderAlpha = border.a / 255.0 * (outer - inner);
        const double alpha = fillAlpha + borderAlpha;
        std::uint8_t* const px = &image.rgba[(static_cast<std::size_t>(y) * image.width + x) * 4];
        if (alpha <= 0.0) {
          px[0] = fill.r;
          px[1] = fill.g;
          px[2] = fill.b;
          px[3] = 0;
          continue;
        }
        px[0] = Byte((fill.r * fillAlpha + border.r * borderAlpha) / alpha);
        px[1] = Byte((fill.g * fillAlpha + border.g * borderAlpha) / alpha);
        px[2] = Byte((fill.b * fillAlpha + border.b * borderAlpha) / alpha);
        px[3] = Byte(alpha * 255.0);
      }
    }
    return image;
  }

  Image DrawCorner(
    const int corner,
    const int radius,
    const Rgba fill,
    const Rgba border,
    const float borderWidth
  )
  {
    const int r = std::max(radius, 1);
    const Image whole = DrawRoundedRect(2 * r, 2 * r, static_cast<float>(r), fill, border, borderWidth);
    const int left = (corner == 1 || corner == 2) ? r : 0;
    const int top = (corner == 2 || corner == 3) ? r : 0;
    Image image;
    image.width = r;
    image.height = r;
    image.rgba.resize(static_cast<std::size_t>(r) * r * 4);
    for (int y = 0; y < r; ++y) {
      std::copy_n(
        &whole.rgba[(static_cast<std::size_t>(top + y) * whole.width + left) * 4],
        static_cast<std::size_t>(r) * 4,
        &image.rgba[static_cast<std::size_t>(y) * r * 4]
      );
    }
    return image;
  }

  std::vector<std::uint8_t> EncodePng(
    const Image& image
  )
  {
    std::vector<std::uint8_t> out = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
    const auto putU32 = [](std::vector<std::uint8_t>& to, const std::uint32_t value) {
      to.push_back(static_cast<std::uint8_t>(value >> 24));
      to.push_back(static_cast<std::uint8_t>(value >> 16));
      to.push_back(static_cast<std::uint8_t>(value >> 8));
      to.push_back(static_cast<std::uint8_t>(value));
    };
    const auto chunk = [&](const char* type, const std::vector<std::uint8_t>& data) {
      putU32(out, static_cast<std::uint32_t>(data.size()));
      const std::size_t typeAt = out.size();
      out.insert(out.end(), type, type + 4);
      out.insert(out.end(), data.begin(), data.end());
      const uLong crc = crc32(0L, &out[typeAt], static_cast<uInt>(4 + data.size()));
      putU32(out, static_cast<std::uint32_t>(crc));
    };
    std::vector<std::uint8_t> header;
    putU32(header, static_cast<std::uint32_t>(image.width));
    putU32(header, static_cast<std::uint32_t>(image.height));
    header.insert(header.end(), {8, 6, 0, 0, 0}); // 8 bits, RGBA, deflate, no filter method, no interlace
    chunk("IHDR", header);
    std::vector<std::uint8_t> raw;
    const std::size_t rowBytes = static_cast<std::size_t>(image.width) * 4;
    raw.reserve((rowBytes + 1) * image.height);
    for (int y = 0; y < image.height; ++y) {
      raw.push_back(0); // filter: none
      const auto row = image.rgba.begin() + static_cast<std::ptrdiff_t>(y * rowBytes);
      raw.insert(raw.end(), row, row + static_cast<std::ptrdiff_t>(rowBytes));
    }
    uLongf packedSize = compressBound(static_cast<uLong>(raw.size()));
    std::vector<std::uint8_t> packed(packedSize);
    if (compress2(packed.data(), &packedSize, raw.data(), static_cast<uLong>(raw.size()), 6) != Z_OK) {
      return {};
    }
    packed.resize(packedSize);
    chunk("IDAT", packed);
    chunk("IEND", {});
    return out;
  }

  namespace
  {
    std::mutex sImagesLock;
    std::map<std::string, std::shared_ptr<const std::vector<std::uint8_t>>> sImages;

    std::string Key(
      const std::string_view path
    )
    {
      std::string key(path);
      std::transform(key.begin(), key.end(), key.begin(), [](const unsigned char c) {
        return c == '\\' ? '/' : static_cast<char>(std::tolower(c));
      });
      return key;
    }
  } // namespace

  bool IsMemoryPath(
    const std::string_view path
  )
  {
    if (path.size() < kMemoryPrefix.size()) {
      return false;
    }
    for (std::size_t i = 0; i < kMemoryPrefix.size(); ++i) {
      const char c = path[i] == '\\' ? '/' : static_cast<char>(std::tolower(static_cast<unsigned char>(path[i])));
      if (c != kMemoryPrefix[i]) {
        return false;
      }
    }
    return true;
  }

  void RegisterImage(
    const std::string& path,
    std::vector<std::uint8_t> bytes
  )
  {
    auto kept = std::make_shared<const std::vector<std::uint8_t>>(std::move(bytes));
    std::lock_guard<std::mutex> lock(sImagesLock);
    sImages[Key(path)] = std::move(kept);
  }

  std::shared_ptr<const std::vector<std::uint8_t>> FindImage(
    const std::string_view path
  )
  {
    std::lock_guard<std::mutex> lock(sImagesLock);
    const auto found = sImages.find(Key(path));
    return found != sImages.end() ? found->second : nullptr;
  }
} // namespace moho::uiart
