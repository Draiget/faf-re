// The terrain library's erosion (src/editor/terrain/EdErosion.cpp, EdFieldEro2.cpp, from FAF Studio): every
// golden case of tests/editor/data/erosion_cases.lua (Studio's selftest_erosion_cases.lua), the solvers'
// properties, the map border, and the local brush (Erode, Rain, Deposit) staying inside its window. The
// stand-alone tool's lab, bench and scale-study modes are kept below but not run.
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "editor/terrain/EdErosion.h"
#include "editor/terrain/EdFieldCore.h"

#include <gtest/gtest.h>

using namespace faf::editor::field;

namespace
{
  namespace er = faf::editor::field::erosion;

#define CHECK(cond, ...)                                                                                               \
  do {                                                                                                                 \
    if (!(cond)) {                                                                                                     \
      char checkMessage[1024];                                                                                         \
      std::snprintf(checkMessage, sizeof(checkMessage), __VA_ARGS__);                                                  \
      ADD_FAILURE_AT(__FILE__, __LINE__) << checkMessage;                                                              \
    }                                                                                                                  \
  } while (0)

  static std::string Hex(
    const std::uint64_t v
  )
  {
    char b[32];
    std::snprintf(b, sizeof(b), "%016llx", static_cast<unsigned long long>(v));
    return b;
  }

  static double Now()
  {
    using namespace std::chrono;
    return duration<double>(steady_clock::now().time_since_epoch()).count();
  }

  static std::vector<std::string> Split(
    const std::string& s,
    const char sep
  )
  {
    std::vector<std::string> out;
    std::string cur;
    for (const char c : s) {
      if (c == sep) {
        out.push_back(cur);
        cur.clear();
      } else {
        cur.push_back(c);
      }
    }
    out.push_back(cur);
    return out;
  }

  static void ParseParams(
    const std::string& text,
    Params& p
  )
  {
    if (text.empty())
      return;
    for (const std::string& kv : Split(text, ',')) {
      const std::size_t eq = kv.find('=');
      if (eq == std::string::npos)
        continue;
      const std::string key = kv.substr(0, eq), val = kv.substr(eq + 1);
      char* end = nullptr;
      const double n = std::strtod(val.c_str(), &end);
      if (!val.empty() && end != nullptr && *end == '\0')
        p.num[key] = n;
      else
        p.str[key] = val;
    }
  }

  static GridPtr Make(
    const std::string& op,
    const std::string& params,
    const std::map<std::string, GridPtr>& in,
    std::map<std::string, Grid>* extra = nullptr
  )
  {
    OpArgs a;
    ParseParams(params, a.p);
    a.in = in;
    a.extra = extra;
    auto g = std::make_shared<Grid>();
    std::string e;
    if (!RunOp(op, a, *g, e)) {
      std::printf("op %s(%s) failed: %s\n", op.c_str(), params.c_str(), e.c_str());
      return nullptr;
    }
    return g;
  }

  /** A mountain field: ridged noise under a broad uplift, in world units (cell 1). */
  static GridPtr Mountains(
    const int n,
    const int seed = 3,
    const char* ampR = "mul=55,add=0",
    const char* ampP = "mul=8,add=0"
  )
  {
    char buf[200], buf2[200];
    std::snprintf(
      buf,
      sizeof(buf),
      "width=%d,height=%d,seed=%d,scale=%d,octaves=3,persistence=0.4",
      n,
      n,
      seed,
      std::max(24, n * 2 / 5)
    );
    std::snprintf(
      buf2, sizeof(buf2), "width=%d,height=%d,seed=%d,scale=%d,octaves=3", n, n, seed + 100, std::max(12, n / 5)
    );
    const GridPtr r = Make("ridged", buf, {});
    const GridPtr p = Make("perlin", buf2, {});
    const GridPtr rr = Make("affine", ampR, {{"a", r}});
    const GridPtr pp = Make("affine", ampP, {{"a", p}});
    return Make("add", "", {{"a", rr}, {"b", pp}});
  }

  /** The lab terrain: ridged fractal noise made of perlin (1 - |2p - 1|, without the lattice seams of the ridged op)
   * with slopes like the stock maps (mean gradient 0.3), range about 10 .. 40. */
  static GridPtr LabTerrain(
    const int n,
    const double amplitude
  )
  {
    char buf[200];
    std::snprintf(
      buf, sizeof(buf), "width=%d,height=%d,seed=21,scale=%d,octaves=5,persistence=0.5", n, n, std::max(32, n / 2)
    );
    const GridPtr p = Make("perlin", buf, {});
    const GridPtr a = Make("affine", "mul=2,add=-1", {{"a", p}});
    const GridPtr b = Make("abs", "", {{"a", a}});
    const GridPtr c = Make("affine", "mul=-1,add=1", {{"a", b}});
    std::snprintf(buf, sizeof(buf), "mul=%g,add=10", amplitude);
    return Make("affine", buf, {{"a", c}});
  }

  // ---- PNG output (stored deflate blocks)
  // ----------------------------------------------------------------------------------------------------------

  static std::uint32_t Crc(
    const std::uint8_t* d,
    const std::size_t n,
    std::uint32_t c = 0xFFFFFFFFu
  )
  {
    static std::uint32_t table[256];
    static bool init = false;
    if (!init) {
      for (std::uint32_t i = 0; i < 256; ++i) {
        std::uint32_t v = i;
        for (int k = 0; k < 8; ++k)
          v = (v & 1) ? 0xEDB88320u ^ (v >> 1) : v >> 1;
        table[i] = v;
      }
      init = true;
    }
    for (std::size_t i = 0; i < n; ++i)
      c = table[(c ^ d[i]) & 0xFF] ^ (c >> 8);
    return c;
  }

  static void Put32(
    std::vector<std::uint8_t>& o,
    const std::uint32_t v
  )
  {
    o.push_back(static_cast<std::uint8_t>(v >> 24));
    o.push_back(static_cast<std::uint8_t>(v >> 16));
    o.push_back(static_cast<std::uint8_t>(v >> 8));
    o.push_back(static_cast<std::uint8_t>(v));
  }

  static void Chunk(
    std::vector<std::uint8_t>& o,
    const char* type,
    const std::vector<std::uint8_t>& data
  )
  {
    Put32(o, static_cast<std::uint32_t>(data.size()));
    std::vector<std::uint8_t> body(type, type + 4);
    body.insert(body.end(), data.begin(), data.end());
    o.insert(o.end(), body.begin(), body.end());
    Put32(o, ~Crc(body.data(), body.size()));
  }

  static void WritePng(
    const std::string& path,
    const int w,
    const int h,
    const std::vector<std::uint8_t>& rgb
  )
  {
    std::vector<std::uint8_t> raw;
    for (int y = 0; y < h; ++y) {
      raw.push_back(0);
      raw.insert(
        raw.end(),
        rgb.begin() + static_cast<std::size_t>(y) * w * 3,
        rgb.begin() + static_cast<std::size_t>(y + 1) * w * 3
      );
    }
    std::vector<std::uint8_t> z = {0x78, 0x01};
    std::size_t pos = 0;
    while (pos < raw.size()) {
      const std::size_t n = std::min<std::size_t>(65535, raw.size() - pos);
      z.push_back(pos + n >= raw.size() ? 1 : 0);
      z.push_back(static_cast<std::uint8_t>(n));
      z.push_back(static_cast<std::uint8_t>(n >> 8));
      z.push_back(static_cast<std::uint8_t>(~n));
      z.push_back(static_cast<std::uint8_t>((~n) >> 8));
      z.insert(z.end(), raw.begin() + pos, raw.begin() + pos + n);
      pos += n;
    }
    std::uint32_t a = 1, b = 0;
    for (const std::uint8_t c : raw) {
      a = (a + c) % 65521;
      b = (b + a) % 65521;
    }
    Put32(z, (b << 16) | a);
    std::vector<std::uint8_t> out = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
    std::vector<std::uint8_t> ihdr;
    Put32(ihdr, w);
    Put32(ihdr, h);
    ihdr.push_back(8);
    ihdr.push_back(2);
    ihdr.push_back(0);
    ihdr.push_back(0);
    ihdr.push_back(0);
    Chunk(out, "IHDR", ihdr);
    Chunk(out, "IDAT", z);
    Chunk(out, "IEND", {});
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(out.data()), static_cast<std::streamsize>(out.size()));
  }

  /** Shaded relief with a hypsometric tint; the picture is scaled to at most 1024 wide by box sampling. */
  static void DumpRelief(
    const std::string& path,
    const Grid& g,
    const float lo,
    const float hi
  )
  {
    const int step = std::max(1, (g.w + 1023) / 1024);
    const int up = g.w <= 300 ? 3 : 1;
    const int pw = g.w / step * up, ph = g.h / step * up;
    std::vector<std::uint8_t> rgb(static_cast<std::size_t>(pw) * ph * 3);
    for (int y = 0; y < ph; ++y) {
      for (int x = 0; x < pw; ++x) {
        const int sx = x / up * step, sy = y / up * step;
        const auto H = [&](const int i, const int j) {
          return g.At(std::max(0, std::min(g.w - 1, i)), std::max(0, std::min(g.h - 1, j)));
        };
        const float gx = (H(sx + 1, sy) - H(sx - 1, sy)) / (2.0f * g.cell);
        const float gz = (H(sx, sy + 1) - H(sx, sy - 1)) / (2.0f * g.cell);
        // light from the north west
        const float shade = std::max(0.15f, std::min(1.2f, 0.7f + (-gx * 0.7f - gz * 0.7f) * 1.8f));
        const float t = std::max(0.0f, std::min(1.0f, (g.At(sx, sy) - lo) / std::max(1e-6f, hi - lo)));
        const float r = (0.25f + 0.55f * t) * shade, gg = (0.35f + 0.45f * t) * shade,
                    b = (0.2f + 0.7f * t * t) * shade;
        const std::size_t o = (static_cast<std::size_t>(y) * pw + x) * 3;
        rgb[o] = static_cast<std::uint8_t>(255.0f * std::min(1.0f, r * 1.3f));
        rgb[o + 1] = static_cast<std::uint8_t>(255.0f * std::min(1.0f, gg * 1.3f));
        rgb[o + 2] = static_cast<std::uint8_t>(255.0f * std::min(1.0f, b * 1.3f));
      }
    }
    WritePng(path, pw, ph, rgb);
  }

  static void DumpMask(
    const std::string& path,
    const Grid& g,
    float hi = -1.0f,
    const bool logScale = false
  )
  {
    const Stats s = Measure(g);
    if (hi <= 0.0f)
      hi = static_cast<float>(s.mean + 3.0 * s.sd);
    if (hi <= 1e-9f)
      hi = 1.0f;
    const int step = std::max(1, (g.w + 1023) / 1024);
    const int pw = g.w / step, ph = g.h / step;
    std::vector<std::uint8_t> rgb(static_cast<std::size_t>(pw) * ph * 3);
    for (int y = 0; y < ph; ++y) {
      for (int x = 0; x < pw; ++x) {
        float t = g.At(x * step, y * step) / hi;
        if (logScale)
          t = std::log1p(g.At(x * step, y * step)) / std::log1p(hi);
        t = std::max(0.0f, std::min(1.0f, t));
        const std::uint8_t v = static_cast<std::uint8_t>(255.0f * t);
        const std::size_t o = (static_cast<std::size_t>(y) * pw + x) * 3;
        rgb[o] = rgb[o + 1] = rgb[o + 2] = v;
      }
    }
    WritePng(path, pw, ph, rgb);
  }

  // ---- presets (the same numbers as erosion.lua)
  // ----------------------------------------------------------------------------------------------------

  struct Preset
  {
    const char* name;
    const char* op;
    const char* params;
  };

  static const Preset kPresets[] = {
    {"hydraulic", "erode_hydraulic", "iterations=300"},
    {"droplet", "erode_droplet", "density=1.0"},
    {"stream", "erode_stream", "iterations=12"},
    // the presets of erosion.lua (keep in sync)
    {"mountain",
     "erode_droplet",
     "density=4,lifetime=70,inertia=0.3,capacity=8,erode=0.6,deposit=0.15,gravity=6,thermal=0.4,thermal_steps=3,talus="
     "0.9,creep=1"},
    {"hills", "erode_hydraulic", "iterations=100,rain=0.006,erosion=0.08,deposition=0.08,thermal=0.25,talus=0.9"},
    {"canyon", "erode_stream", "iterations=14,k=1.5,max_cut=0.7,diffusion=0.05,widen=2,talus=1.2,area_min=40"},
    {"alpine",
     "erode_droplet",
     "density=3,lifetime=80,inertia=0.2,capacity=6,erode=0.5,deposit=0.05,gravity=8,thermal=0.6,thermal_steps=6,talus="
     "0.7,creep=0.75"},
    {"desert",
     "erode_droplet",
     "density=0.6,lifetime=60,capacity=6,erode=0.4,deposit=0.2,thermal=0.6,thermal_steps=6,talus=0.7,drop_vary=0.8"},
    {"river", "erode_stream", "iterations=20,k=0.5,m=0.5,diffusion=0.3,widen=2,area_min=60,talus=0.5"},
  };

  // ---- tests
  // ------------------------------------------------------------------------------------------------------------------------------------------

  struct Case
  {
    std::string label, op, params, inputs, golden;
  };

  static std::vector<std::string> gLines;
  static std::vector<Case> gCases;
  static std::size_t gBegin = 0, gEnd = 0;
  static std::map<std::string, GridPtr> gFix;

  static bool LoadCases(
    const std::string& path
  )
  {
    std::ifstream in(path, std::ios::binary);
    if (!in)
      return false;
    std::string line;
    while (std::getline(in, line)) {
      if (!line.empty() && line.back() == '\r')
        line.pop_back();
      gLines.push_back(line);
    }
    bool inside = false;
    for (std::size_t i = 0; i < gLines.size(); ++i) {
      const std::string& l = gLines[i];
      if (!inside) {
        if (l.find("Cases = [[") == 0) {
          inside = true;
          gBegin = i + 1;
        }
        continue;
      }
      if (l.find("]]") == 0) {
        gEnd = i;
        break;
      }
      if (l.empty() || l[0] == '#')
        continue;
      const std::vector<std::string> f = Split(l, '|');
      if (f.size() < 5)
        continue;
      gCases.push_back({f[0], f[1], f[2], f[3], f[4]});
    }
    return !gCases.empty();
  }

  static void BuildFixtures()
  {
    // H: a 65 x 65 mountain field, R: a rock hardness mask, F: a flat plate
    gFix["H"] = Mountains(65, 11);
    gFix["R"] = Make("perlin", "width=65,height=65,seed=4,scale=14,octaves=3", {});
    gFix["F"] = Make("const", "width=33,height=33,value=10", {});
  }

  static std::map<std::string, GridPtr> InputsOf(
    const std::string& spec
  )
  {
    std::map<std::string, GridPtr> in;
    for (const std::string& kv : Split(spec, ',')) {
      const std::size_t eq = kv.find('=');
      if (eq != std::string::npos)
        in[kv.substr(0, eq)] = gFix[kv.substr(eq + 1)];
    }
    return in;
  }

  static void TestGoldens(
    const bool update
  )
  {
    const int orig = Threads();
    const int counts[] = {1, 2, 3, 5, 8};
    std::vector<std::string> now;
    for (const int tc : counts) {
      SetThreads(tc);
      BuildFixtures();
      for (std::size_t i = 0; i < gCases.size(); ++i) {
        const Case& c = gCases[i];
        const GridPtr g = Make(c.op, c.params, InputsOf(c.inputs));
        if (!g) {
          CHECK(false, "case %s failed", c.label.c_str());
          if (tc == counts[0])
            now.push_back("0");
          continue;
        }
        const std::string hex = Hex(Checksum(*g));
        if (tc == counts[0])
          now.push_back(hex);
        else
          CHECK(
            hex == now[i],
            "case %s differs with %d threads (%s vs %s)",
            c.label.c_str(),
            tc,
            hex.c_str(),
            now[i].c_str()
          );
      }
    }
    SetThreads(orig);
    int wrong = 0;
    for (std::size_t i = 0; i < gCases.size(); ++i) {
      if (gCases[i].golden != now[i]) {
        ++wrong;
        if (!update)
          std::printf(
            "golden %s: file %s, now %s\n", gCases[i].label.c_str(), gCases[i].golden.c_str(), now[i].c_str()
          );
      }
    }
    if (update) {
      // rewrite the golden column in the file lines
      std::size_t ci = 0;
      for (std::size_t i = gBegin; i < gEnd; ++i) {
        std::string& l = gLines[i];
        if (l.empty() || l[0] == '#')
          continue;
        const std::vector<std::string> f = Split(l, '|');
        if (f.size() < 5)
          continue;
        l = f[0] + "|" + f[1] + "|" + f[2] + "|" + f[3] + "|" + now[ci++];
      }
    } else {
      CHECK(wrong == 0, "%d golden checksums differ (run with --update after checking the change)", wrong);
    }
    std::printf("goldens: %zu cases, %d differ%s\n", gCases.size(), wrong, update ? " (updated)" : "");
  }

  static double Sum(
    const std::vector<float>& v
  )
  {
    double s = 0.0;
    for (const float x : v)
      s += x;
    return s;
  }

  static void TestProperties()
  {
    SetThreads(4);
    // 1. a flat plate stays (nearly) flat for every solver (the droplets may carve the faint ramp that lets water leave
    // a flat)
    const GridPtr flat = Make("const", "width=48,height=48,value=10", {});
    for (const Preset& p : kPresets) {
      const GridPtr r = Make(p.op, p.params, {{"a", flat}});
      const Stats s = Measure(*r);
      // (hillslope creep spreads what the droplets take at the border over the plate: a smooth sag of a few percent, no
      // relief)
      CHECK(
        r && std::fabs(s.min - 10.0f) < 0.25f && std::fabs(s.max - 10.0f) < 0.25f,
        "%s: a flat plate changed (%f .. %f)",
        p.name,
        s.min,
        s.max
      );
    }
    // 2. mass: the hydraulic solver with closed edges and settling keeps the total height (rain evaporates, sediment
    // settles)
    {
      const GridPtr H = Mountains(97, 5);
      std::map<std::string, Grid> extra;
      const GridPtr r = Make("erode_hydraulic", "iterations=120,edge=closed,settle=1", {{"a", H}}, &extra);
      const double before = Sum(H->v), after = Sum(r->v);
      CHECK(std::fabs(before - after) / before < 2e-3, "hydraulic closed: mass changed %g -> %g", before, after);
      CHECK(
        extra.count("wear") && extra.count("deposit") && extra.count("flow") && extra.count("water") &&
          extra.count("sediment"),
        "extra outputs missing"
      );
      const Stats w = Measure(extra["wear"]), d = Measure(extra["deposit"]);
      CHECK(w.min >= 0.0f && d.min >= 0.0f, "wear / deposit negative");
      CHECK(w.max > 0.0f, "no wear at all");
      // wear - deposit = height lost
      double net = 0.0;
      for (std::size_t i = 0; i < H->v.size(); ++i)
        net += static_cast<double>(extra["wear"].v[i]) - extra["deposit"].v[i] - (H->v[i] - r->v[i]);
      CHECK(std::fabs(net) / before < 2e-3, "wear - deposit does not match the height change (%g)", net);
      // the border is left alone with pinned edges
      const GridPtr p = Make("erode_hydraulic", "iterations=40,edge=pinned", {{"a", H}});
      bool same = true;
      for (int x = 0; x < H->w; ++x) {
        same = same && p->At(x, 0) == H->At(x, 0) && p->At(x, H->h - 1) == H->At(x, H->h - 1);
      }
      CHECK(same, "the pinned border changed");
    }
    // 3. erosion lowers the high ground and does not run away
    {
      const GridPtr H = Mountains(97, 6);
      for (const Preset& pr : kPresets) {
        const GridPtr r = Make(pr.op, pr.params, {{"a", H}});
        const Stats a = Measure(*H), b = Measure(*r);
        CHECK(b.max <= a.max + 0.5f, "%s raised the peak (%f -> %f)", pr.name, a.max, b.max);
        CHECK(b.min >= a.min - 1.0f, "%s dug %f below the lowest point", pr.name, a.min - b.min);
        CHECK(std::isfinite(b.mean) && std::isfinite(b.sd), "%s produced non-finite values", pr.name);
        CHECK(r->v != H->v, "%s changed nothing", pr.name);
      }
    }
    // 4. erodibility mask 0 protects the terrain
    {
      const GridPtr H = Mountains(65, 7);
      const GridPtr zero = Make("const", "width=65,height=65,value=0", {});
      const GridPtr r = Make("erode_hydraulic", "iterations=60,settle=0", {{"a", H}, {"mask", zero}});
      // no dissolving: heights only change by deposit of nothing -> identical
      CHECK(r->v == H->v, "a zero erodibility mask still changed the terrain");
    }
    // 5. the brush session: deterministic, bounded, only the window changes
    {
      const int n = 129;
      const GridPtr H = Mountains(n, 8);
      std::vector<std::uint16_t> words(H->Count());
      for (std::size_t i = 0; i < words.size(); ++i)
        words[i] = static_cast<std::uint16_t>(std::floor(H->v[i] * 128.0f + 0.5f));
      auto run = [&](const int threads) {
        SetThreads(threads);
        er::ErodeSession s;
        s.Begin(n, n, words.data(), er::HydroParams());
        std::vector<std::uint16_t> cur = words;
        for (int k = 0; k < 6; ++k) {
          er::BrushDab d;
          d.cx = 50.0 + k * 3.0;
          d.cz = 60.0;
          d.radius = 14;
          d.iterations = 10;
          int x0, z0, x1, z1;
          std::vector<std::uint16_t> w;
          CHECK(s.Dab(d, x0, z0, x1, z1, w), "dab failed");
          for (int z = z0; z <= z1; ++z)
            for (int x = x0; x <= x1; ++x)
              cur[static_cast<std::size_t>(z) * n + x] = w[static_cast<std::size_t>(z - z0) * (x1 - x0 + 1) + (x - x0)];
        }
        return cur;
      };
      const std::vector<std::uint16_t> a = run(1), b = run(7);
      CHECK(a == b, "the brush session depends on the thread count");
      int changed = 0, outside = 0;
      for (int z = 0; z < n; ++z) {
        for (int x = 0; x < n; ++x) {
          const std::size_t i = static_cast<std::size_t>(z) * n + x;
          if (a[i] != words[i]) {
            ++changed;
            if (x < 20 || x > 90 || z < 30 || z > 90)
              ++outside;
          }
        }
      }
      CHECK(changed > 0, "the brush changed nothing");
      CHECK(outside == 0, "the brush changed %d samples far outside its window", outside);
    }

    std::printf("properties done\n");
  }

  // ---- the map boundary
  // ---------------------------------------------------------------------------------------------------------------------------

  /** Mean |h(edge) - h(edge + 1)| over the four sides (corners left out): a vertical wall or lip at the border shows up
   * as a jump of this step. */
  static double EdgeStep(
    const Grid& g
  )
  {
    double s = 0.0;
    int n = 0;
    for (int i = 2; i < g.w - 2; ++i) {
      s += std::fabs(g.At(i, 0) - g.At(i, 1)) + std::fabs(g.At(i, g.h - 1) - g.At(i, g.h - 2));
      n += 2;
    }
    for (int j = 2; j < g.h - 2; ++j) {
      s += std::fabs(g.At(0, j) - g.At(1, j)) + std::fabs(g.At(g.w - 1, j) - g.At(g.w - 2, j));
      n += 2;
    }
    return s / n;
  }

  /** Mean change |after - before| of the outermost cells over the mean change of the cells 8 .. 12 in from the border:
   * a ring that is left out (or hit twice as hard) breaks this. */
  static double EdgeChangeRatio(
    const Grid& before,
    const Grid& after
  )
  {
    double edge = 0.0, inner = 0.0;
    int ne = 0, ni = 0;
    for (int z = 0; z < before.h; ++z) {
      for (int x = 0; x < before.w; ++x) {
        const int d = std::min(std::min(x, before.w - 1 - x), std::min(z, before.h - 1 - z));
        const double c = std::fabs(static_cast<double>(after.At(x, z)) - before.At(x, z));
        if (d == 0) {
          edge += c;
          ++ne;
        } else if (d >= 8 && d <= 12) {
          inner += c;
          ++ni;
        }
      }
    }
    return (edge / ne) / std::max(1e-9, inner / ni);
  }

  /** A hilly field with a tilt, so water and droplets run towards and over the borders. */
  static GridPtr Tilted(
    const int n,
    const int seed,
    const double tilt
  )
  {
    const GridPtr M = Mountains(n, seed);
    auto g = std::make_shared<Grid>(*M);
    for (int z = 0; z < n; ++z)
      for (int x = 0; x < n; ++x)
        g->At(x, z) += static_cast<float>(tilt * (std::fabs(x - 0.5 * n) + 0.7 * std::fabs(z - 0.5 * n)));
    return g;
  }

  static void TestBoundary()
  {
    SetThreads(4);
    struct Case
    {
      const char* name;
      const char* op;
      const char* params;
    };
    static const Case cases[] = {
      {"hydraulic", "erode_hydraulic", "iterations=200,rain=0.006,erosion=0.12"},
      {"hydraulic thermal", "erode_hydraulic", "iterations=120,thermal=0.5,talus=0.6"},
      {"droplet", "erode_droplet", "density=3,lifetime=60,seed=4"},
      {"droplet thermal", "erode_droplet", "density=3,lifetime=40,seed=5,thermal=0.5,thermal_steps=10"},
      {"stream", "erode_stream", "iterations=12,uplift=0.2"},
    };
    for (const double tilt : {0.0, 0.25, -0.25}) {
      const GridPtr H = Tilted(129, 12, tilt);
      const double before = EdgeStep(*H);
      for (const Case& c : cases) {
        const GridPtr r = Make(c.op, c.params, {{"a", H}});
        const double after = EdgeStep(*r);
        const double ratio = EdgeChangeRatio(*H, *r);
        std::printf(
          "boundary tilt %+.2f %-18s edge step %.3f -> %.3f, edge change / inner change %.2f\n",
          tilt,
          c.name,
          before,
          after,
          ratio
        );
        CHECK(
          after <= before * 1.2 + 0.05, "%s (tilt %g): a step at the border: %.3f -> %.3f", c.name, tilt, before, after
        );
        CHECK(
          ratio > 0.25 && ratio < 2.5,
          "%s (tilt %g): the border cells change %.2f times as much as the inside (a pinned ring changes 0, a clipped "
          "brush 2 and more)",
          c.name,
          tilt,
          ratio
        );
      }
    }
  }

  /** The local brushes (erode, rain, deposit) at the map border: the stroke runs along the left and top edge of a
   * tilted field. */
  static void TestBrushBoundary()
  {
    SetThreads(2);
    const int n = 97;
    const GridPtr H = Tilted(n, 13, 0.3);
    std::vector<std::uint16_t> words(H->Count());
    for (std::size_t i = 0; i < words.size(); ++i)
      words[i] = static_cast<std::uint16_t>(std::floor(H->v[i] * 128.0f + 0.5f));
    for (int mode = 0; mode < 3; ++mode) {
      er::ErodeSession s;
      er::HydroParams hp; // the strokes of the editor use rates like these (erosionbrush.lua)
      hp.rain = 0.012f;
      hp.erosion = 0.3f;
      hp.deposition = 0.1f;
      hp.thermal = 0.3f;
      s.Begin(n, n, words.data(), hp);
      Grid cur = *H;
      auto put = [&](const int x0, const int z0, const int x1, const int z1, const std::vector<std::uint16_t>& w) {
        for (int z = z0; z <= z1; ++z)
          for (int x = x0; x <= x1; ++x)
            cur.At(x, z) = static_cast<float>(w[static_cast<std::size_t>(z - z0) * (x1 - x0 + 1) + (x - x0)]) / 128.0f;
      };
      for (int k = 0; k < 10; ++k) {
        for (int side = 0; side < 2; ++side) {
          er::BrushDab d;
          d.mode = mode;
          d.radius = 12;
          d.cx = side == 0 ? 2.0 : 10.0 + k * 7.0;
          d.cz = side == 0 ? 10.0 + k * 7.0 : 2.0;
          d.iterations = 24;
          d.amount = 1.5;
          int x0, z0, x1, z1;
          std::vector<std::uint16_t> w;
          if (s.Dab(d, x0, z0, x1, z1, w))
            put(x0, z0, x1, z1, w);
        }
      }
      int x0, z0, x1, z1;
      std::vector<std::uint16_t> w;
      if (s.Finish(x0, z0, x1, z1, w))
        put(x0, z0, x1, z1, w);
      // the left column x = 0 and the top row z = 0, compared with the step the field had
      double b = 0.0, a = 0.0;
      int cnt = 0;
      for (int i = 2; i < n - 2; ++i) {
        b += std::fabs(H->At(0, i) - H->At(1, i)) + std::fabs(H->At(i, 0) - H->At(i, 1));
        a += std::fabs(cur.At(0, i) - cur.At(1, i)) + std::fabs(cur.At(i, 0) - cur.At(i, 1));
        cnt += 2;
      }
      b /= cnt;
      a /= cnt;
      std::printf(
        "brush mode %d: edge step %.3f -> %.3f, edge change / inner change %.2f\n", mode, b, a, EdgeChangeRatio(*H, cur)
      );
      CHECK(a <= b * 1.2 + 0.05, "brush mode %d: a step at the map border: %.3f -> %.3f", mode, b, a);
    }
  }

  // ---- the local brush: locality, falloff, isotropy, relief
  // ---------------------------------------------------------------------------------------
  //
  // What the erosion brush must do (the user's report: it went beyond its circle, left a square patch with a straight
  // edge, dug only in the centre and at the rim, drew parallel comb grooves along a ridge and flattened the mountain):
  // change nothing outside the radius (exactly), follow the brush weight inside, not depend on the window it was solved
  // in, have no preferred direction on the grid, make branching uneven relief and keep the height, spread and mass of
  // the mountain.

#ifdef OLD_BRUSH
  // (building this test against the brush of commit 009f88a / ef5c44a for before / after numbers: the window rule it
  // had)
  namespace faf::editor::field::erosion
  {
    inline void BrushWindow(
      const BrushDab& dab,
      const int w,
      const int h,
      int& x0,
      int& z0,
      int& x1,
      int& z1
    )
    {
      const double radius = std::max(1.0, dab.radius);
      const double margin = dab.margin >= 0.0 ? dab.margin : (dab.mode == 1 ? 0.8 : 0.35) * radius + 3.0;
      x0 = std::max(0, static_cast<int>(std::floor(dab.cx - radius - margin)) - 1);
      z0 = std::max(0, static_cast<int>(std::floor(dab.cz - radius - margin)) - 1);
      x1 = std::min(w - 1, static_cast<int>(std::ceil(dab.cx + radius + margin)) + 1);
      z1 = std::min(h - 1, static_cast<int>(std::ceil(dab.cz + radius + margin)) + 1);
    }
  } // namespace faf::editor::field::erosion
#endif

  namespace
  {
    using Words = std::vector<std::uint16_t>;

    Words ToWords(
      const std::vector<float>& h
    )
    {
      Words w(h.size());
      for (std::size_t i = 0; i < w.size(); ++i)
        w[i] = static_cast<std::uint16_t>(std::floor(h[i] * 128.0f + 0.5f));
      return w;
    }

    /** Smooth value noise 0..1 of feature size `scale` samples (a hash lattice with smoothstep blending: no periodic
     * pattern a comb detector could lock onto). */
    double ValueNoise(
      const double x,
      const double z,
      const double scale,
      const unsigned seed
    )
    {
      const auto lat = [seed](const int ix, const int iz) {
        unsigned u = static_cast<unsigned>(ix) * 73856093u ^ static_cast<unsigned>(iz) * 19349663u ^ seed * 83492791u;
        u ^= u >> 13;
        u *= 0x5bd1e995u;
        u ^= u >> 15;
        return static_cast<double>(u & 0xffffu) / 65535.0;
      };
      const double u = x / scale, v = z / scale;
      const int ix = static_cast<int>(std::floor(u)), iz = static_cast<int>(std::floor(v));
      double fx = u - ix, fz = v - iz;
      fx = fx * fx * (3.0 - 2.0 * fx);
      fz = fz * fz * (3.0 - 2.0 * fz);
      const double a = lat(ix, iz) * (1.0 - fx) + lat(ix + 1, iz) * fx,
                   b = lat(ix, iz + 1) * (1.0 - fx) + lat(ix + 1, iz + 1) * fx;
      return a * (1.0 - fz) + b * fz;
    }

    /** A round mountain: `height` over a base of 10, gaussian of `sigma` samples, centred on the field; `ripple` adds
     * soft bumps (value noise of 24 and 10 samples, amplitude `ripple`). */
    std::vector<float> RoundMountain(
      const int n,
      const double height,
      const double sigma,
      const double ripple
    )
    {
      std::vector<float> h(static_cast<std::size_t>(n) * n);
      const double c = 0.5 * (n - 1);
      for (int z = 0; z < n; ++z) {
        for (int x = 0; x < n; ++x) {
          const double r2 = ((x - c) * (x - c) + (z - c) * (z - c)) / (sigma * sigma);
          const double bump =
            ripple * ((ValueNoise(x, z, 24.0, 5u) - 0.5) * 2.0 + 0.5 * (ValueNoise(x, z, 10.0, 9u) - 0.5) * 2.0);
          h[static_cast<std::size_t>(z) * n + x] = static_cast<float>(10.0 + height * std::exp(-r2) + bump);
        }
      }
      return h;
    }

    /** A ridge along x (crest at the middle row) with a wavy crest and soft bumps. */
    std::vector<float> RidgeField(
      const int n,
      const double height,
      const double halfWidth,
      const double ripple
    )
    {
      std::vector<float> h = RoundMountain(n, 0.0, 1.0, ripple);
      const double c = 0.5 * (n - 1);
      for (int z = 0; z < n; ++z) {
        for (int x = 0; x < n; ++x) {
          const double dz = (z - c) / halfWidth;
          const double crest = 1.0 + 0.12 * std::sin(x * 0.11) + 0.08 * std::sin(x * 0.037 + 1.0);
          h[static_cast<std::size_t>(z) * n + x] += static_cast<float>(height * crest * std::exp(-dz * dz));
        }
      }
      return h;
    }

    /** A tilted plane with soft bumps (every point has the same slope: only the brush weights can make the profile). */
    std::vector<float> SlopeField(
      const int n,
      const double slope,
      const double ripple
    )
    {
      std::vector<float> h = RoundMountain(n, 0.0, 1.0, ripple);
      for (int z = 0; z < n; ++z)
        for (int x = 0; x < n; ++x)
          h[static_cast<std::size_t>(z) * n + x] +=
            static_cast<float>(100.0 - slope * 0.8 * (x - 0.5 * (n - 1)) - slope * 0.6 * (z - 0.5 * (n - 1)));
      return h;
    }

    struct StrokeSpec
    {
      int mode = 0;
      double radius = 12;
      double falloff = 1.0;
      int iterations = 8;
      double margin = -1;
      double strength = 1.0;
      double amount = 0.5;
      er::HydroParams hp;
      std::vector<std::pair<double, double>> centres;
      int shape = 0; // 1: an elliptic mask weight (a shaped brush), 2: the same plus a 1e-3 perturbation
    };

    /** The brush values of erosionbrush.lua. */
    er::HydroParams EditorParams()
    {
      er::HydroParams hp;
      hp.rain = 0.006f;
      hp.evaporation = 0.02f;
      hp.gain = 0.08f;
      hp.capacity = 1.0f;
      hp.erosion = 0.2f;
      hp.deposition = 0.1f;
      hp.thermal = 0.15f;
      hp.talus = 0.8f;
      hp.vary = 0.3f;
      hp.vary_scale = 30.0f;
      return hp;
    }

    Words RunStroke(
      const int n,
      const Words& start,
      const StrokeSpec& s
    )
    {
      er::ErodeSession se;
      se.Begin(n, n, start.data(), s.hp);
      Words cur = start;
      for (const auto& c : s.centres) {
        er::BrushDab d;
        d.mode = s.mode;
        d.cx = c.first;
        d.cz = c.second;
        d.radius = s.radius;
        d.falloff = s.falloff;
        d.iterations = s.iterations;
        d.margin = s.margin;
        d.strength = s.strength;
        d.amount = s.amount;
        int x0, z0, x1, z1;
        if (s.shape != 0) {
          er::BrushWindow(d, n, n, x0, z0, x1, z1);
          for (int z = z0; z <= z1; ++z) {
            for (int x = x0; x <= x1; ++x) {
              const double dx = x - d.cx, dz = z - d.cz;
              const double u = std::sqrt((dx * dx) / 1.0 + (dz * dz) / 0.45) / s.radius; // an ellipse: wider than high
              float w = u >= 1.0 ? 0.0f : static_cast<float>(0.5 * (1.0 + std::cos(3.14159265358979 * u)));
              if (s.shape == 2 && w > 0.0f)
                w = std::max(0.0f, w * (1.0f + 1e-3f * static_cast<float>(std::sin(1.7 * x + 2.3 * z))));
              d.weights.push_back(w);
            }
          }
        }
        std::vector<std::uint16_t> w;
        if (!se.Dab(d, x0, z0, x1, z1, w))
          continue;
        for (int z = z0; z <= z1; ++z)
          for (int x = x0; x <= x1; ++x)
            cur[static_cast<std::size_t>(z) * n + x] = w[static_cast<std::size_t>(z - z0) * (x1 - x0 + 1) + (x - x0)];
      }
      int x0, z0, x1, z1;
      std::vector<std::uint16_t> w;
      if (se.Finish(x0, z0, x1, z1, w)) {
        for (int z = z0; z <= z1; ++z)
          for (int x = x0; x <= x1; ++x)
            cur[static_cast<std::size_t>(z) * n + x] = w[static_cast<std::size_t>(z - z0) * (x1 - x0 + 1) + (x - x0)];
      }
      return cur;
    }

    /** Dab centres along a horizontal line through (cx, cz), `count` of them `spacing` apart, centred on cx. */
    std::vector<std::pair<double, double>> Line(
      const double cx,
      const double cz,
      const int count,
      const double spacing
    )
    {
      std::vector<std::pair<double, double>> v;
      for (int k = 0; k < count; ++k)
        v.push_back({cx + (k - 0.5 * (count - 1)) * spacing, cz});
      return v;
    }

    /** Distance of (x, z) to the segment the dab centres lie on. */
    double DistToCentres(
      const std::vector<std::pair<double, double>>& c,
      const int x,
      const int z
    )
    {
      double best = 1e30;
      for (std::size_t i = 0; i + 1 <= c.size(); ++i) {
        const double ax = c[i].first, az = c[i].second;
        const double bx = i + 1 < c.size() ? c[i + 1].first : ax, bz = i + 1 < c.size() ? c[i + 1].second : az;
        const double vx = bx - ax, vz = bz - az, l2 = vx * vx + vz * vz;
        double t = l2 > 0.0 ? ((x - ax) * vx + (z - az) * vz) / l2 : 0.0;
        t = std::max(0.0, std::min(1.0, t));
        best = std::min(best, std::hypot(x - (ax + t * vx), z - (az + t * vz)));
      }
      return best;
    }

    double Cv(
      const std::vector<double>& v
    )
    {
      double m = 0.0, m2 = 0.0;
      for (const double x : v) {
        m += x;
        m2 += x * x;
      }
      m /= static_cast<double>(v.size());
      m2 /= static_cast<double>(v.size());
      return std::sqrt(std::max(0.0, m2 - m * m)) / std::max(1e-12, m);
    }

    /** Mean |laplacian| over the samples within `radius` of the dab centres: the high frequency relief. */
    double Roughness(
      const Words& w,
      const int n,
      const std::vector<std::pair<double, double>>& c,
      const double radius
    )
    {
      double s = 0.0;
      int k = 0;
      for (int z = 1; z < n - 1; ++z) {
        for (int x = 1; x < n - 1; ++x) {
          if (DistToCentres(c, x, z) > radius)
            continue;
          const std::size_t i = static_cast<std::size_t>(z) * n + x;
          s += std::fabs(static_cast<double>(w[i - 1]) + w[i + 1] + w[i - n] + w[i + n] - 4.0 * w[i]) / 128.0;
          ++k;
        }
      }
      return s / std::max(1, k);
    }

    struct Change
    {
      int outside = 0; // samples beyond `limit` of the centres that differ
      double maxOutside = 0.0;
      double meanAbs = 0.0;  // inside
      double cv = 0.0;       // coefficient of variation of the block means of |change| inside
      double net = 0.0;      // sum of the change inside (volume)
      double gross = 0.0;    // sum of |change|
      double peakDrop = 0.0; // highest sample before - after
      double sdBefore = 0.0, sdAfter = 0.0;
    };

    Change Compare(
      const Words& before,
      const Words& after,
      const int n,
      const std::vector<std::pair<double, double>>& c,
      const double radius,
      const double limit
    )
    {
      Change r;
      std::vector<double> blocks;
      double cnt = 0.0, mb = 0.0, ma = 0.0;
      for (int z = 0; z < n; ++z) {
        for (int x = 0; x < n; ++x) {
          const std::size_t i = static_cast<std::size_t>(z) * n + x;
          const double d = DistToCentres(c, x, z);
          const double ch = (static_cast<double>(after[i]) - before[i]) / 128.0;
          if (d > limit) {
            if (ch != 0.0) {
              ++r.outside;
              r.maxOutside = std::max(r.maxOutside, std::fabs(ch));
            }
          } else if (d <= radius) {
            r.meanAbs += std::fabs(ch);
            r.net += ch;
            cnt += 1.0;
            mb += before[i] / 128.0;
            ma += after[i] / 128.0;
          }
        }
      }
      r.gross = r.meanAbs;
      r.meanAbs /= std::max(1.0, cnt);
      mb /= std::max(1.0, cnt);
      ma /= std::max(1.0, cnt);
      for (int z = 0; z < n; ++z) {
        for (int x = 0; x < n; ++x) {
          if (DistToCentres(c, x, z) > radius)
            continue;
          const std::size_t i = static_cast<std::size_t>(z) * n + x;
          r.sdBefore += (before[i] / 128.0 - mb) * (before[i] / 128.0 - mb);
          r.sdAfter += (after[i] / 128.0 - ma) * (after[i] / 128.0 - ma);
          r.peakDrop = std::max(r.peakDrop, (static_cast<double>(before[i]) - after[i]) / 128.0);
        }
      }
      r.sdBefore = std::sqrt(r.sdBefore / std::max(1.0, cnt));
      r.sdAfter = std::sqrt(r.sdAfter / std::max(1.0, cnt));
      // 4 x 4 blocks wholly inside 0.8 of the radius
      for (int z = 0; z + 4 <= n; z += 4) {
        for (int x = 0; x + 4 <= n; x += 4) {
          bool in = true;
          for (int q = 0; q < 4 && in; ++q)
            for (int p = 0; p < 4; ++p)
              if (DistToCentres(c, x + p, z + q) > 0.8 * radius) {
                in = false;
                break;
              }
          if (!in)
            continue;
          double s = 0.0;
          for (int q = 0; q < 4; ++q)
            for (int p = 0; p < 4; ++p)
              s += std::fabs(
                     static_cast<double>(after[static_cast<std::size_t>(z + q) * n + x + p]) -
                     before[static_cast<std::size_t>(z + q) * n + x + p]
                   ) /
                128.0;
          blocks.push_back(s / 16.0);
        }
      }
      r.cv = blocks.empty() ? 0.0 : Cv(blocks);
      return r;
    }

    double Peak(
      const Words& w
    )
    {
      return *std::max_element(w.begin(), w.end()) / 128.0;
    }
  } // namespace

  static void TestBrushQuality()
  {
    SetThreads(2);
    const int n = 161;
    const double c = 0.5 * (n - 1);
    // 1. the change is exactly zero outside the brush, whatever the radius, falloff, slope, mode, window margin or
    // brush shape
    {
      struct Terrain
      {
        const char* name;
        std::vector<float> h;
      };
      const Terrain terrains[] = {
        {"mountain", RoundMountain(n, 40.0, 22.0, 0.4)},
        {"slope", SlopeField(n, 0.9, 0.3)},
        {"ridge", RidgeField(n, 35.0, 14.0, 0.5)}
      };
      int worstOutside = 0;
      for (const Terrain& t : terrains) {
        const Words base = ToWords(t.h);
        for (const double radius : {3.0, 12.0, 40.0}) {
          for (const double falloff : {0.0, 0.5, 1.0}) {
            for (int mode = 0; mode < 3; ++mode) {
              StrokeSpec s;
              s.mode = mode;
              s.radius = radius;
              s.falloff = falloff;
              s.hp = EditorParams();
              s.centres = Line(c + 3.0, c - 4.0, 5, radius / 3.0);
              const double reach = mode == 1 ? 0.9 * (0.8 * radius + 3.0) : 0.0;
              const Words after = RunStroke(n, base, s);
              const Change ch = Compare(base, after, n, s.centres, radius, radius + reach + 0.5);
              worstOutside = std::max(worstOutside, ch.outside);
              CHECK(
                ch.outside == 0,
                "%s r=%g falloff=%g mode %d: %d samples changed outside the brush (max %.3f)",
                t.name,
                radius,
                falloff,
                mode,
                ch.outside,
                ch.maxOutside
              );
              CHECK(
                ch.gross > 0.0 || radius < 4.0,
                "%s r=%g falloff=%g mode %d: the brush changed nothing",
                t.name,
                radius,
                falloff,
                mode
              );
            }
          }
        }
      }
      // a shaped brush (weights from a mask), and one whose weights differ by 1e-3: the result differs a little, not
      // chaotically (no threshold on the weights)
      const Words base = ToWords(RoundMountain(n, 40.0, 22.0, 0.4));
      StrokeSpec s;
      s.radius = 14;
      s.hp = EditorParams();
      s.centres = Line(c, c, 6, 4.0);
      s.shape = 1;
      const Words a = RunStroke(n, base, s);
      s.shape = 2;
      const Words b = RunStroke(n, base, s);
      const Change ca = Compare(base, a, n, s.centres, 14.0, 14.5);
      double worst = 0.0;
      for (std::size_t i = 0; i < a.size(); ++i)
        worst = std::max(worst, std::fabs(static_cast<double>(a[i]) - b[i]) / 128.0);
      std::printf(
        "brush shape: outside %d, mean |change| %.4f, worst change under a 1e-3 mask change %.4f\n",
        ca.outside,
        ca.meanAbs,
        worst
      );
      CHECK(ca.outside == 0, "a shaped brush changed %d samples outside its mask", ca.outside);
      CHECK(worst < 0.1, "a 1e-3 change of the brush mask changed the result by %.3f (chaotic)", worst);
    }
    // 2. no window artifact: the result does not depend on the window the dab is solved in (the old brush solved a
    // square window with a fixed rim: straight edges, stranded water)
    {
      const Words base = ToWords(RoundMountain(n, 40.0, 22.0, 0.4));
      for (const int mode : {0, 2}) { // (the rain brush's margin is its reach: a different margin is a different brush)
        StrokeSpec s;
        s.mode = mode;
        s.radius = 12;
        s.hp = EditorParams();
        s.centres = Line(c, c, 12, 4.0);
        s.margin = 0.0;
        const Words tight = RunStroke(n, base, s);
        s.margin = 17.0;
        const Words wide = RunStroke(n, base, s);
        int differ = 0;
        for (std::size_t i = 0; i < tight.size(); ++i)
          differ += tight[i] != wide[i] ? 1 : 0;
        CHECK(differ == 0, "mode %d: the result depends on the size of the window (%d samples differ)", mode, differ);
      }
    }
    // 3. the change follows the brush falloff: on a plane (the same slope everywhere) the radial profile of the change,
    // averaged over many independent dabs, is smooth and spread over the
    //    brush (the old brush dug in the centre and at the rim and left the middle out)
    {
      const Words base = ToWords(SlopeField(n, 0.7, 0.35));
      double sum[5] = {}, cnt[5] = {};
      for (int k = 0; k < 40; ++k) {
        StrokeSpec s;
        s.radius = 20;
        s.hp = EditorParams();
        s.iterations = 16;
        s.centres.push_back({c + std::fmod(0.37 * k, 3.0), c + std::fmod(0.61 * k, 3.0)});
#ifndef OLD_BRUSH
        s.hp.seed = static_cast<std::uint32_t>(k + 1);
#endif
        const Words after = RunStroke(n, base, s);
        for (int z = 0; z < n; ++z) {
          for (int x = 0; x < n; ++x) {
            const double d = std::hypot(x - s.centres[0].first, z - s.centres[0].second) / s.radius;
            if (d >= 1.0)
              continue;
            const int b = static_cast<int>(d * 5.0);
            sum[b] += std::fabs(
                        static_cast<double>(after[static_cast<std::size_t>(z) * n + x]) -
                        base[static_cast<std::size_t>(z) * n + x]
                      ) /
              128.0;
            cnt[b] += 1.0;
          }
        }
      }
      double prof[5];
      for (int b = 0; b < 5; ++b)
        prof[b] = sum[b] / cnt[b];
      std::printf(
        "radial profile of |change| (plane, 5 rings of the radius): %.4f %.4f %.4f %.4f %.4f\n",
        prof[0],
        prof[1],
        prof[2],
        prof[3],
        prof[4]
      );
      // the brush weight of the rings: 0.97 0.80 0.52 0.22 0.04. The change may not be much steeper than that, may not
      // leave a ring out and may not pile up at the rim
      const double top = std::max(prof[0], std::max(prof[1], prof[2]));
      CHECK(
        prof[2] > 0.3 * top && prof[1] > 0.3 * top && prof[0] > 0.3 * top,
        "a ring in the middle of the brush is hardly eroded (%.4f %.4f %.4f)",
        prof[0],
        prof[1],
        prof[2]
      );
      CHECK(
        prof[4] < 0.3 * top && prof[3] < 0.9 * top,
        "the rim of the brush is dug as much as its middle (rings 4 / 5: %.4f %.4f, top %.4f)",
        prof[3],
        prof[4],
        top
      );
      for (int b = 1; b < 5; ++b)
        CHECK(
          prof[b] < prof[b - 1] * 1.7 + 1e-4,
          "the profile is not smooth: ring %d %.4f after %.4f",
          b + 1,
          prof[b],
          prof[b - 1]
        );
    }
    // 4. no preferred direction on the grid: a round mountain, the same brush on its flank from many dabs: the change
    // in the sectors along the axes and along the diagonals is alike
    {
      const Words base = ToWords(RoundMountain(n, 40.0, 22.0, 0.0));
      StrokeSpec s;
      s.radius = 24;
      s.hp = EditorParams();
      s.hp.vary = 0.0f;
      s.hp.thermal = 0.0f;
      s.iterations = 8;
      for (int k = 0; k < 60; ++k)
        s.centres.push_back({c, c});
      const Words after = RunStroke(n, base, s);
      double axis = 0.0, diag = 0.0, na = 0.0, nd = 0.0;
      for (int z = 0; z < n; ++z) {
        for (int x = 0; x < n; ++x) {
          const double dx = x - c, dz = z - c, r = std::hypot(dx, dz) / s.radius;
          if (r < 0.25 || r > 0.85)
            continue;
          const double ang = std::fmod(std::atan2(dz, dx) + 2.0 * 3.14159265358979, 3.14159265358979 / 2.0) /
            (3.14159265358979 / 2.0); // 0 .. 1 within a quadrant: 0 and 1 = along an axis
          const double ch = std::fabs(
                              static_cast<double>(after[static_cast<std::size_t>(z) * n + x]) -
                              base[static_cast<std::size_t>(z) * n + x]
                            ) /
            128.0;
          if (ang < 0.17 || ang > 0.83) {
            axis += ch;
            na += 1.0;
          } else if (ang > 0.33 && ang < 0.67) {
            diag += ch;
            nd += 1.0;
          }
        }
      }
      const double ratio = (axis / na) / std::max(1e-9, diag / nd);
      std::printf("isotropy: mean |change| along the axes / along the diagonals = %.2f\n", ratio);
      CHECK(
        ratio > 0.7 && ratio < 1.43, "the erosion has a preferred direction on the grid: axes / diagonals = %.2f", ratio
      );
    }
    // 5. a stroke over a mountain: it keeps its summit, spread and mass, makes uneven relief, and no comb: the high
    // pass of the change has no regular period along the stroke
    {
      for (int kind = 0; kind < 3; ++kind) {
        const Words base = ToWords(
          kind == 0 ? RoundMountain(n, 40.0, 24.0, 1.2)
                    : (kind == 1 ? RidgeField(n, 35.0, 14.0, 1.2) : RidgeField(n, 35.0, 14.0, 0.12))
        );
        StrokeSpec s;
        s.radius = 12;
        s.hp = EditorParams();
        s.centres = Line(c, c, 40, 4.0); // 40 dabs, spacing radius / 3: what a stroke of the editor does
        const Words after = RunStroke(n, base, s);
        const Change ch = Compare(base, after, n, s.centres, 12.0, 12.5);
        const double r0 = Roughness(base, n, s.centres, 12.0), r1 = Roughness(after, n, s.centres, 12.0);
        const double peak0 = Peak(base), peak1 = Peak(after);
        std::printf(
          "stroke over a %s: outside %d, peak %.2f -> %.2f, sd in the brush %.3f -> %.3f (%.1f%%), mean|change| %.3f, "
          "cv %.2f, net %.1f gross %.1f, relief %.4f -> %.4f\n",
          kind == 0 ? "mountain" : (kind == 1 ? "ridge" : "smooth ridge"),
          ch.outside,
          peak0,
          peak1,
          ch.sdBefore,
          ch.sdAfter,
          100.0 * (ch.sdAfter - ch.sdBefore) / ch.sdBefore,
          ch.meanAbs,
          ch.cv,
          ch.net,
          ch.gross,
          r0,
          r1
        );
        CHECK(ch.outside == 0, "the stroke changed %d samples outside the brush", ch.outside);
        CHECK(
          peak0 - peak1 < 0.01 * (peak0 - 10.0),
          "the summit dropped by %.3f (%.2f%% of the mountain)",
          peak0 - peak1,
          100.0 * (peak0 - peak1) / (peak0 - 10.0)
        );
        CHECK(
          std::fabs(ch.sdAfter - ch.sdBefore) < 0.04 * ch.sdBefore,
          "the spread of the heights in the brush changed from %.3f to %.3f",
          ch.sdBefore,
          ch.sdAfter
        );
        CHECK(r1 > 1.15 * r0, "the relief did not increase (%.4f -> %.4f)", r0, r1);
        CHECK(ch.cv > (kind == 0 ? 0.6 : 0.35), "the erosion is too even: cv %.2f", ch.cv);
        CHECK(ch.meanAbs > 0.02 && ch.meanAbs < 0.6, "the stroke strength is off: mean |change| %.3f", ch.meanAbs);
        double volume = 0.0; // the mountain above its base inside the brush
        for (int z = 0; z < n; ++z)
          for (int x = 0; x < n; ++x)
            if (DistToCentres(s.centres, x, z) <= 12.0)
              volume += (static_cast<double>(base[static_cast<std::size_t>(z) * n + x]) / 128.0 - 10.0);
        CHECK(
          ch.net > -0.015 * volume,
          "the stroke lost too much mass: net %.1f of the %.0f in the brush (%.2f%%)",
          ch.net,
          volume,
          100.0 * ch.net / volume
        );
        std::printf(
          "   mass: net %.1f of the %.0f above the base in the brush (%.2f%%)\n",
          ch.net,
          volume,
          100.0 * ch.net / volume
        );
        // comb: the change along x on the rows of the stroke, high passed; the strongest correlation at a lag of 3 ..
        // 12 samples
        double best = 0.0;
        for (int zr = static_cast<int>(c) - 8; zr <= static_cast<int>(c) + 8; zr += 4) {
          std::vector<double> d;
          for (int x = 40; x < n - 40; ++x)
            d.push_back(
              (static_cast<double>(after[static_cast<std::size_t>(zr) * n + x]) -
               base[static_cast<std::size_t>(zr) * n + x]) /
              128.0
            );
          std::vector<double> hp(d.size(), 0.0);
          for (std::size_t i = 4; i + 4 < d.size(); ++i) {
            double m = 0.0;
            for (int k = -4; k <= 4; ++k)
              m += d[i + k];
            hp[i] = d[i] - m / 9.0;
          }
          double v0 = 0.0;
          for (const double x : hp)
            v0 += x * x;
          for (int lag = 3; lag <= 12; ++lag) {
            double a = 0.0;
            for (std::size_t i = 8; i + lag + 8 < hp.size(); ++i)
              a += hp[i] * hp[i + lag];
            best = std::max(best, a / std::max(1e-12, v0));
          }
        }
        std::printf(
          "   comb: strongest correlation of the high passed change at a lag of 3 .. 12 samples: %.2f\n", best
        );
        CHECK(best < 0.5, "the change along the stroke repeats at a regular spacing (correlation %.2f): a comb", best);
      }
    }
    // 6. determinism, and a different stroke position gives a different pattern
    {
      const Words base = ToWords(RoundMountain(n, 40.0, 24.0, 1.2));
      StrokeSpec s;
      s.hp = EditorParams();
      s.centres = Line(c, c, 10, 4.0);
      SetThreads(1);
      const Words a = RunStroke(n, base, s);
      SetThreads(5);
      const Words b = RunStroke(n, base, s);
      CHECK(a == b, "the brush depends on the thread count");
      SetThreads(2);
    }
    // 7. the brush at the map border keeps working (corner dabs): no samples outside the radius even there
    {
      const Words base = ToWords(RoundMountain(n, 40.0, 60.0, 0.4));
      StrokeSpec s;
      s.radius = 14;
      s.hp = EditorParams();
      s.centres = {{1.0, 1.0}, {3.0, 2.0}, {5.0, 2.0}, {n - 2.0, n - 2.0}, {n - 5.0, n - 3.0}};
      for (int mode = 0; mode < 3; ++mode) {
        s.mode = mode;
        const Words after = RunStroke(n, base, s);
        int out = 0;
        const double reach = mode == 1 ? 0.9 * (0.8 * 14 + 3.0) : 0.0;
        for (int z = 0; z < n; ++z)
          for (int x = 0; x < n; ++x)
            if (
              after[static_cast<std::size_t>(z) * n + x] != base[static_cast<std::size_t>(z) * n + x] &&
              DistToCentres(s.centres, x, z) > 14.0 + reach + 0.5
            )
              ++out;
        CHECK(out == 0, "mode %d at the map border: %d samples changed outside the brush", mode, out);
      }
    }
  }

  // ---- variation, height preservation, conservation
  // ---------------------------------------------------------------------------------------------

  /** How unevenly the erosion is spread over the map: the coefficient of variation of the mean |change| of 8 x 8 blocks
   * (0 = every block is changed alike, the evenly spaced look of uniform rain and identical droplets). */
  static double RegionalVariation(
    const Grid& before,
    const Grid& after,
    double* meanChange = nullptr
  )
  {
    const int B = 8,
              margin =
                16; // the blocks cover the map without its border strip (edge effects are not what is measured here)
    const int iw = before.w - 2 * margin, ih = before.h - 2 * margin;
    double sum[B][B] = {}, cnt[B][B] = {};
    double all = 0.0;
    for (int z = margin; z < before.h - margin; ++z) {
      for (int x = margin; x < before.w - margin; ++x) {
        const double c = std::fabs(static_cast<double>(after.At(x, z)) - before.At(x, z));
        sum[(z - margin) * B / ih][(x - margin) * B / iw] += c;
        cnt[(z - margin) * B / ih][(x - margin) * B / iw] += 1.0;
        all += c;
      }
    }
    double m = 0.0, m2 = 0.0;
    for (int j = 0; j < B; ++j)
      for (int i = 0; i < B; ++i) {
        const double v = sum[j][i] / cnt[j][i];
        m += v;
        m2 += v * v;
      }
    m /= B * B;
    m2 /= B * B;
    if (meanChange != nullptr)
      *meanChange = all / static_cast<double>(iw * ih);
    return std::sqrt(std::max(0.0, m2 - m * m)) / std::max(1e-9, m);
  }

  static double Total(
    const Grid& g
  )
  {
    return Sum(g.v);
  }

  /** A noisy hillside: a tilted plane with gentle noise on it (what uniform rain and identical droplets turn into
   * evenly spaced parallel rills). */
  static GridPtr Hillside(
    const int n,
    const int seed
  )
  {
    char buf[160];
    std::snprintf(
      buf, sizeof(buf), "width=%d,height=%d,seed=%d,scale=%d,octaves=4,persistence=0.5", n, n, seed, std::max(16, n / 3)
    );
    const GridPtr p = Make("perlin", buf, {});
    auto g = std::make_shared<Grid>(*p);
    for (int z = 0; z < n; ++z)
      for (int x = 0; x < n; ++x)
        g->At(x, z) = 1.5f * p->At(x, z) + 0.35f * static_cast<float>(x) + 0.2f * static_cast<float>(z) + 20.0f;
    return g;
  }

  static void TestVariation()
  {
    SetThreads(4);
    const GridPtr M = Mountains(129, 21);
    const GridPtr H = Hillside(129, 21);
    struct Case
    {
      const char* name;
      const char* op;
      const char* base;
      const char* vary;
    };
    static const Case cases[] = {
      {"hydraulic", "erode_hydraulic", "iterations=200", "vary=0.9,vary_scale=40,rain_vary=0.8"},
      {"droplet", "erode_droplet", "density=2,seed=3", "vary=0.9,vary_scale=40,rain_vary=0.8,drop_vary=0.8"},
      {"stream", "erode_stream", "iterations=8,k=0.5", "vary=0.9,vary_scale=40,rain_vary=0.8,jitter=0.5"},
    };
    for (const Case& c : cases) {
      const GridPtr plain = Make(c.op, c.base, {{"a", H}});
      const GridPtr varied = Make(c.op, (std::string(c.base) + "," + c.vary).c_str(), {{"a", H}});
      double m0 = 0.0, m1 = 0.0;
      const double v0 = RegionalVariation(*H, *plain, &m0), v1 = RegionalVariation(*H, *varied, &m1);
      std::printf(
        "variation %-10s regional variation %.3f -> %.3f (mean change %.3f -> %.3f)\n", c.name, v0, v1, m0, m1
      );
      CHECK(
        v1 > v0 * 1.08, "%s: the variation options do not make the erosion more uneven (%.3f -> %.3f)", c.name, v0, v1
      );
      CHECK(varied->v != plain->v, "%s: the variation options changed nothing", c.name);
      // thread independence of the new paths
      SetThreads(1);
      const GridPtr again = Make(c.op, (std::string(c.base) + "," + c.vary).c_str(), {{"a", H}});
      SetThreads(4);
      CHECK(again->v == varied->v, "%s: the variation depends on the thread count", c.name);
      // a different seed gives a different pattern
      const GridPtr other = Make(c.op, (std::string(c.base) + "," + c.vary + ",seed=77").c_str(), {{"a", H}});
      CHECK(other->v != varied->v, "%s: the seed does not change the variation", c.name);
    }
    // keep range, max change (on the mountain field)
    const Stats hs = Measure(*M);
    for (const Case& c : cases) {
      const GridPtr kept = Make(c.op, (std::string(c.base) + ",keep_range=1").c_str(), {{"a", M}});
      const Stats ks = Measure(*kept);
      const auto pct = [](std::vector<float> v, const double q) {
        std::sort(v.begin(), v.end());
        return v[static_cast<std::size_t>(q * static_cast<double>(v.size() - 1))];
      };
      const float span = hs.max - hs.min;
      CHECK(
        ks.min >= hs.min - 1e-3f && ks.max <= hs.max + 1e-3f,
        "%s: keep_range left the input range: %f .. %f (input %f .. %f)",
        c.name,
        ks.min,
        ks.max,
        hs.min,
        hs.max
      );
      CHECK(
        std::fabs(pct(kept->v, 0.01) - pct(M->v, 0.01)) < 0.04f * span &&
          std::fabs(pct(kept->v, 0.99) - pct(M->v, 0.99)) < 0.04f * span,
        "%s: keep_range: the 1%% / 99%% heights are %f / %f, the input's %f / %f",
        c.name,
        pct(kept->v, 0.01),
        pct(kept->v, 0.99),
        pct(M->v, 0.01),
        pct(M->v, 0.99)
      );
      const GridPtr capped = Make(c.op, (std::string(c.base) + ",max_change=1.5").c_str(), {{"a", M}});
      double worst = 0.0;
      for (std::size_t i = 0; i < M->v.size(); ++i)
        worst = std::max(worst, std::fabs(static_cast<double>(capped->v[i]) - M->v[i]));
      CHECK(worst <= 1.5 + 1e-3, "%s: max_change 1.5 left a change of %f", c.name, worst);
      const GridPtr plain = Make(c.op, c.base, {{"a", M}});
      double worstPlain = 0.0;
      for (std::size_t i = 0; i < M->v.size(); ++i)
        worstPlain = std::max(worstPlain, std::fabs(static_cast<double>(plain->v[i]) - M->v[i]));
      std::printf(
        "range %-10s plain %.2f .. %.2f (max change %.2f), kept %.2f .. %.2f, input %.2f .. %.2f\n",
        c.name,
        Measure(*plain).min,
        Measure(*plain).max,
        worstPlain,
        ks.min,
        ks.max,
        hs.min,
        hs.max
      );
    }
    // conserve: the volume the run lost comes back
    for (const Case& c : cases) {
      const GridPtr plain = Make(c.op, c.base, {{"a", M}});
      const GridPtr kept = Make(c.op, (std::string(c.base) + ",conserve=1").c_str(), {{"a", M}});
      const double t0 = Total(*M), t1 = Total(*plain), t2 = Total(*kept);
      std::printf("volume %-10s lost %.4f%% -> %.6f%%\n", c.name, 100.0 * (t0 - t1) / t0, 100.0 * (t0 - t2) / t0);
      CHECK(std::fabs(t0 - t2) / t0 < 1e-3, "%s: conserve=1 left a volume change of %g", c.name, (t0 - t2) / t0);
    }
    // protect: the summits keep more of their height
    for (const Case& c : cases) {
      const GridPtr plain = Make(c.op, c.base, {{"a", M}});
      const GridPtr prot = Make(c.op, (std::string(c.base) + ",protect=1").c_str(), {{"a", M}});
      std::vector<float> sorted = M->v;
      std::sort(sorted.begin(), sorted.end());
      const float top = sorted[sorted.size() * 95 / 100];
      double d0 = 0.0, d1 = 0.0;
      int cnt = 0;
      for (std::size_t i = 0; i < M->v.size(); ++i) {
        if (M->v[i] < top)
          continue;
        d0 += M->v[i] - plain->v[i];
        d1 += M->v[i] - prot->v[i];
        ++cnt;
      }
      std::printf("protect %-10s the top 5%% lose %.3f -> %.3f on average\n", c.name, d0 / cnt, d1 / cnt);
      CHECK(
        d1 <= d0 * 0.8 + 1e-3, "%s: protect=1 does not spare the summits (%.3f -> %.3f)", c.name, d0 / cnt, d1 / cnt
      );
    }
  }

  static void TestSolverExtras()
  {
    SetThreads(4);
    // droplets on a real slope: with the old speed rule (accel 0) the speed fell to 0 on the first steps and (almost)
    // nothing was dug
    {
      const GridPtr slope = Hillside(129, 5);
      const GridPtr fixedRule = Make("erode_droplet", "density=2,seed=3", {{"a", slope}});
      const GridPtr oldRule = Make("erode_droplet", "density=2,seed=3,accel=0", {{"a", slope}});
      double mf = 0.0, mo = 0.0;
      RegionalVariation(*slope, *fixedRule, &mf);
      RegionalVariation(*slope, *oldRule, &mo);
      std::printf("droplet speed rule: mean change accel=1 %.4f, accel=0 %.4f\n", mf, mo);
      CHECK(
        mf > 20.0 * mo && mf > 0.05, "droplets still dig (almost) nothing on a slope: %.4f vs the old rule %.4f", mf, mo
      );
    }
    // the local brush with hard / soft ground: same pattern for every dab, differs from the plain brush
    {
      const int n = 97;
      const GridPtr B = Mountains(n, 30);
      std::vector<std::uint16_t> words(B->Count());
      for (std::size_t i = 0; i < words.size(); ++i)
        words[i] = static_cast<std::uint16_t>(std::floor(B->v[i] * 128.0f + 0.5f));
      auto stroke = [&](const float vary) {
        er::HydroParams hp;
        hp.rain = 0.012f;
        hp.erosion = 0.3f;
        hp.vary = vary;
        er::ErodeSession s;
        s.Begin(n, n, words.data(), hp);
        std::vector<std::uint16_t> cur = words;
        for (int k = 0; k < 8; ++k) {
          er::BrushDab d;
          d.cx = 30.0 + k * 5.0;
          d.cz = 48.0;
          d.radius = 12;
          d.iterations = 16;
          int x0, z0, x1, z1;
          std::vector<std::uint16_t> w;
          if (s.Dab(d, x0, z0, x1, z1, w))
            for (int z = z0; z <= z1; ++z)
              for (int x = x0; x <= x1; ++x)
                cur[static_cast<std::size_t>(z) * n + x] =
                  w[static_cast<std::size_t>(z - z0) * (x1 - x0 + 1) + (x - x0)];
        }
        return cur;
      };
      const std::vector<std::uint16_t> plain = stroke(0.0f), varied = stroke(0.9f), again = stroke(0.9f);
      CHECK(varied == again, "the brush with variation is not repeatable");
      CHECK(varied != plain, "the brush variation changed nothing");
    }
  }

  /** Mean |Laplacian| over the interior: how much fine relief (gullies, ridges) a terrain has. */
  static double MeanAbsLaplacian(
    const Grid& g
  )
  {
    double sum = 0.0;
    std::size_t count = 0;
    for (int z = 1; z < g.h - 1; ++z) {
      for (int x = 1; x < g.w - 1; ++x) {
        sum += std::fabs(4.0 * g.At(x, z) - g.At(x - 1, z) - g.At(x + 1, z) - g.At(x, z - 1) - g.At(x, z + 1));
        ++count;
      }
    }
    return count > 0 ? sum / static_cast<double>(count) : 0.0;
  }

  /** Share of the samples that moved by more than `limit` units. */
  static double ShareMoved(
    const Grid& before,
    const Grid& after,
    const float limit
  )
  {
    std::size_t n = 0;
    for (std::size_t i = 0; i < before.v.size(); ++i)
      if (std::fabs(after.v[i] - before.v[i]) > limit)
        ++n;
    return static_cast<double>(n) / static_cast<double>(std::max<std::size_t>(1, before.v.size()));
  }

  static double MeanChange(
    const Grid& before,
    const Grid& after
  )
  {
    double s = 0.0;
    for (std::size_t i = 0; i < before.v.size(); ++i)
      s += std::fabs(after.v[i] - before.v[i]);
    return s / static_cast<double>(std::max<std::size_t>(1, before.v.size()));
  }

  /**
   * The droplet feedback rounds and the stream power law. Seen on rendered test terrains (hillshade of rolling hills
   * with cliffs and of a rough mountain field, before / after in the design document): (1) with 4 rounds every droplet
   * digs a lone groove (a smear of short worms, few samples moved by more than half a unit, little fine relief); with
   * 32 rounds the droplets of a round follow the valleys the earlier rounds dug (a dozen times more of the terrain is
   * dissected and the fine relief doubles). (2) The stream solver used to cut at its cap everywhere (k = 0.5 and k = 4
   * gave the same result); now the cut share is F / (1 + F) with F = k * catchment^m, so k scales the change.
   */
  static void TestFeedbackAndHierarchy()
  {
    SetThreads(4);
    const GridPtr H = LabTerrain(161, 19.0);
    {
      // smooth rolling hills (the stock maps' ground): there the gullies of a droplet run are the only fine relief
      const GridPtr P = Make("perlin", "width=161,height=161,seed=7,scale=60,octaves=2", {});
      const GridPtr S = Make("affine", "mul=14,add=20", {{"a", P}});
      const double base = MeanAbsLaplacian(*S);
      // (without creep: what the feedback does on its own; TestVeins is about what creep does to it)
      const GridPtr few = Make("erode_droplet", "density=2,seed=3,rounds=4,creep=0", {{"a", S}});
      const GridPtr many = Make("erode_droplet", "density=2,seed=3,rounds=32,creep=0", {{"a", S}});
      const double rf = MeanAbsLaplacian(*few), rm = MeanAbsLaplacian(*many);
      const double mf = ShareMoved(*S, *few, 0.5f), mm = ShareMoved(*S, *many, 0.5f);
      std::printf(
        "droplet rounds 4 -> 32 on smooth hills: fine relief %.4f -> %.4f (input %.4f), samples moved > 0.5: %.3f -> "
        "%.3f\n",
        rf,
        rm,
        base,
        mf,
        mm
      );
      CHECK(rm > 1.3 * rf, "32 feedback rounds do not give more fine relief than 4: %.4f vs %.4f", rm, rf);
      CHECK(rm > 1.5 * base, "32 feedback rounds add too little relief to the input: %.4f vs %.4f", rm, base);
      CHECK(mm > 2.0 * mf, "32 rounds do not reach more of the terrain than 4: %.3f vs %.3f", mm, mf);
    }
    {
      double change[3];
      const char* params[3] = {
        "iterations=8,area_min=20,k=0.02", "iterations=8,area_min=20,k=0.1", "iterations=8,area_min=20,k=0.5"
      };
      for (int i = 0; i < 3; ++i)
        change[i] = MeanChange(*H, *Make("erode_stream", params[i], {{"a", H}}));
      std::printf("stream k 0.02 / 0.1 / 0.5: mean change %.4f %.4f %.4f\n", change[0], change[1], change[2]);
      CHECK(
        change[1] > 1.15 * change[0] && change[2] > 1.15 * change[1],
        "the stream erodibility no longer scales the change: %.4f %.4f %.4f",
        change[0],
        change[1],
        change[2]
      );
    }
    {
      const GridPtr narrow = Make("erode_stream", "iterations=8,area_min=20,k=0.1,width_vary=0", {{"a", H}});
      const GridPtr wide = Make("erode_stream", "iterations=8,area_min=20,k=0.1,width_vary=1", {{"a", H}});
      const double sn = ShareMoved(*H, *narrow, 0.02f), sw = ShareMoved(*H, *wide, 0.02f);
      std::printf("stream valley width growth 0 -> 1: samples moved > 0.02: %.3f -> %.3f\n", sn, sw);
      CHECK(sw > 1.05 * sn, "valleys of big rivers are not wider with width_vary: %.3f vs %.3f", sw, sn);
    }
    {
      const GridPtr every1 = Make("erode_stream", "iterations=8,area_min=20,k=0.1,route_every=1", {{"a", H}});
      const GridPtr every3 = Make("erode_stream", "iterations=8,area_min=20,k=0.1,route_every=3", {{"a", H}});
      double diff = 0.0;
      for (std::size_t i = 0; i < every1->v.size(); ++i)
        diff += std::fabs(every1->v[i] - every3->v[i]);
      diff /= static_cast<double>(every1->v.size());
      const double change = MeanChange(*H, *every1);
      std::printf("stream route_every 1 vs 3: mean difference %.4f of a mean change %.4f\n", diff, change);
      CHECK(
        diff < 0.5 * change,
        "recomputing the rivers every 3 steps changes the result too much: %.4f vs %.4f",
        diff,
        change
      );
    }
  }

  // ---- veins: the comb along crests and mound edges
  // ------------------------------------------------------------------------------------------------

  /** Smooth mounds (a Gaussian each, slopes up to ~0.4 near the rim, relief 18): the droplets' flow diverges on every
   * one of them, which is where the comb shows (rendered: radial fungus like ribs). */
  static GridPtr Mounds(
    const int n
  )
  {
    auto g = std::make_shared<Grid>(n, n, 1.0f, 0.0f, 0.0f);
    struct M
    {
      double x, z, w, a;
    };
    static const M mounds[] = {
      {0.28, 0.34, 0.12, 14.0},
      {0.60, 0.28, 0.095, 10.0},
      {0.72, 0.62, 0.14, 16.0},
      {0.35, 0.72, 0.105, 11.0},
      {0.50, 0.50, 0.08, 8.0}
    };
    for (int z = 0; z < n; ++z) {
      for (int x = 0; x < n; ++x) {
        double h = 0.0;
        for (const M& m : mounds) {
          const double dx = x - m.x * n, dz = z - m.z * n, w = m.w * n;
          h += m.a * std::exp(-(dx * dx + dz * dz) / (w * w));
        }
        // a little smooth undulation, so the flanks are not perfectly symmetric
        h += 1.5 * std::sin(0.045 * x + 0.5) * std::cos(0.037 * z) + 0.8 * std::sin(0.11 * x + 0.17 * z);
        g->At(x, z) = static_cast<float>(h + 3.0);
      }
    }
    return g;
  }

  /** Binomial blur of a field, `passes` times (variance passes / 2 per axis). */
  static std::vector<float> BlurField(
    std::vector<float> v,
    const int w,
    const int h,
    const int passes
  )
  {
    std::vector<float> tmp(v.size());
    for (int p = 0; p < passes; ++p) {
      for (int z = 0; z < h; ++z)
        for (int x = 0; x < w; ++x)
          tmp[z * w + x] =
            0.25f * v[z * w + std::max(0, x - 1)] + 0.5f * v[z * w + x] + 0.25f * v[z * w + std::min(w - 1, x + 1)];
      for (int z = 0; z < h; ++z)
        for (int x = 0; x < w; ++x)
          v[z * w + x] = 0.25f * tmp[std::max(0, z - 1) * w + x] + 0.5f * tmp[z * w + x] +
            0.25f * tmp[std::min(h - 1, z + 1) * w + x];
    }
    return v;
  }

  struct VeinStats
  {
    double lap1 = 0.0;  // mean |Laplacian at 1 cell| of the change over the mean |change|: grooves of 1 cell width are
                        // all Laplacian (a groove 2 cells wide has 1/4 of it)
    double band = 0.0;  // share of the change's energy in the 1 .. 4 cell band (difference of two blurs): the comb
                        // (evenly spaced thin grooves), a smooth valley has none of it
    double cover = 0.0; // (sum |change|)^2 / (n * sum change^2) over the eroded ground: 1 = the change is the same
                        // everywhere, small = it sits in a few lines
    double axes = 0.0, diagonals = 0.0; // orientation of the fine change: mean power in the 10 degrees around the grid
                                        // axes / diagonals over the mean (1 = no grid direction preferred)
  };

  static VeinStats MeasureVeins(
    const Grid& before,
    const Grid& after
  )
  {
    const int w = before.w, h = before.h, m = 8;
    std::vector<float> d(before.v.size());
    for (std::size_t i = 0; i < d.size(); ++i)
      d[i] = before.v[i] - after.v[i];
    VeinStats r;
    double sumAbs = 0.0, sumLap = 0.0, sumSq = 0.0, sumAbsSlope = 0.0;
    std::size_t n = 0, nl = 0;
    for (int z = m; z < h - m; ++z) {
      for (int x = m; x < w - m; ++x) {
        const std::size_t i = static_cast<std::size_t>(z) * w + x;
        sumAbs += std::fabs(d[i]);
        sumSq += static_cast<double>(d[i]) * d[i];
        sumLap += std::fabs(
          4.0 * (after.v[i] - before.v[i]) - (after.v[i - 1] - before.v[i - 1]) - (after.v[i + 1] - before.v[i + 1]) -
          (after.v[i - w] - before.v[i - w]) - (after.v[i + w] - before.v[i + w])
        );
        ++nl;
        if (std::fabs(d[i]) > 0.0f)
          ++n;
        (void)sumAbsSlope;
      }
    }
    r.lap1 = (sumLap / std::max<std::size_t>(1, nl)) / std::max(1e-9, sumAbs / std::max<std::size_t>(1, nl));
    const std::vector<float> b1 = BlurField(d, w, h, 2), b4 = BlurField(d, w, h, 32);
    double band = 0.0;
    for (int z = m; z < h - m; ++z)
      for (int x = m; x < w - m; ++x) {
        const std::size_t i = static_cast<std::size_t>(z) * w + x;
        const double v = static_cast<double>(b1[i]) - b4[i];
        band += v * v;
      }
    r.band = band / std::max(1e-9, sumSq);
    const double cnt = static_cast<double>(std::max<std::size_t>(1, nl));
    r.cover = (sumAbs * sumAbs) / std::max(1e-9, cnt * sumSq);
    // orientation of the fine change (gradient of the high passed change, power weighted)
    std::vector<float> hp(d.size());
    const std::vector<float> b3 = BlurField(d, w, h, 18);
    for (std::size_t i = 0; i < d.size(); ++i)
      hp[i] = d[i] - b3[i];
    double hist[36] = {};
    double total = 0.0;
    for (int z = m + 1; z < h - m - 1; ++z)
      for (int x = m + 1; x < w - m - 1; ++x) {
        const std::size_t i = static_cast<std::size_t>(z) * w + x;
        const double gx = 0.5 * (hp[i + 1] - hp[i - 1]), gz = 0.5 * (hp[i + w] - hp[i - w]);
        const double p = gx * gx + gz * gz;
        double a = std::atan2(gz, gx) * 180.0 / 3.14159265358979323846;
        if (a < 0.0)
          a += 180.0;
        if (a >= 180.0)
          a -= 180.0;
        hist[std::min(35, static_cast<int>(a / 5.0))] += p;
        total += p;
      }
    if (total > 0.0) {
      for (double& x : hist)
        x = x / total * 36.0;
      r.axes = 0.25 * (hist[0] + hist[17] + hist[18] + hist[35]);
      r.diagonals = 0.25 * (hist[8] + hist[9] + hist[26] + hist[27]);
    }
    return r;
  }

  /**
   * Terrain "veins": repeated droplet erosion of a smooth mound or mountain used to leave a comb: a main ridge (the
   * crest) with evenly spaced razor thin grooves running off it on both sides (a fungus like radial comb on every
   * mound), while the broad slopes between stayed smooth. Seen on rendered hillshades (FAF Studio's
   * docs/projects/editor/TERRAIN_GEN_DESIGN.md, update "veins"): (1) droplets dig lines; the ridge between two lines is
   * dug by nothing (no water runs on a divide), so it keeps its old height while both sides sink: that spine is the
   * vein, and the next round's droplets are caught by the deepened grooves (the feedback of the 32 rounds), which
   * deepens them more with every pass; (2) the spacing of the grooves is the width of the digging brush, whatever the
   * steering (blurring the steering surface, random turns, a smoother or wider brush, multi scale steering only move
   * the spacing); (3) there is no hillslope creep: the walls never slump. The fix is creep (diffusion of the change
   * made so far, after every round). Measured here on mounds after three passes (seed 1, 2, 3) with creep 0 (the old
   * behaviour) and the default: the 1 cell Laplacian of the change, the share of the change in the 1 .. 4 cell band,
   * and that neither the grid axes nor the diagonals are preferred.
   */
  static void TestVeins()
  {
    SetThreads(4);
    const GridPtr M = Mounds(161);
    const char* creepOff = "density=2,creep=0";
    const char* creepOn = "density=2";
    GridPtr cur[2] = {M, M};
    const char* mode[2] = {creepOff, creepOn};
    VeinStats vs[2][3];
    double mass[2] = {0.0, 0.0};
    for (int pass = 0; pass < 3; ++pass) {
      for (int k = 0; k < 2; ++k) {
        cur[k] =
          Make("erode_droplet", (std::string(mode[k]) + ",seed=" + std::to_string(pass + 1)).c_str(), {{"a", cur[k]}});
        vs[k][pass] = MeasureVeins(*M, *cur[k]);
      }
    }
    for (int k = 0; k < 2; ++k)
      mass[k] = MeanChange(*M, *cur[k]);
    for (int k = 0; k < 2; ++k)
      std::printf(
        "veins %-10s pass 1/2/3: 1 cell Laplacian share %.3f %.3f %.3f, 1..4 cell band %.3f %.3f %.3f, cover %.2f %.2f "
        "%.2f, axes %.2f diagonals %.2f (mean change %.3f)\n",
        k == 0 ? "creep 0" : "creep 2",
        vs[k][0].lap1,
        vs[k][1].lap1,
        vs[k][2].lap1,
        vs[k][0].band,
        vs[k][1].band,
        vs[k][2].band,
        vs[k][0].cover,
        vs[k][1].cover,
        vs[k][2].cover,
        vs[k][2].axes,
        vs[k][2].diagonals,
        mass[k]
      );
    // grooves at least 2 cells wide: the 1 cell Laplacian of the change is a clear fraction of what the old grooves
    // had, on every pass
    for (int pass = 0; pass < 3; ++pass) {
      CHECK(
        vs[1][pass].lap1 < 0.4 * vs[0][pass].lap1,
        "pass %d: creep leaves razor thin grooves (1 cell Laplacian share %.3f vs %.3f without)",
        pass + 1,
        vs[1][pass].lap1,
        vs[0][pass].lap1
      );
      CHECK(
        vs[1][pass].band < 0.5 * vs[0][pass].band,
        "pass %d: the comb band keeps its energy (%.3f vs %.3f without creep)",
        pass + 1,
        vs[1][pass].band,
        vs[0][pass].band
      );
    }
    // the grooves do not get sharper pass after pass (they used to): the fine share of the third pass is not above the
    // first one's by more than a little
    CHECK(
      vs[1][2].lap1 < 1.3 * vs[1][0].lap1 + 0.01,
      "the veins deepen with every pass (1 cell Laplacian share %.3f -> %.3f)",
      vs[1][0].lap1,
      vs[1][2].lap1
    );
    // creep does not take the erosion away: about as much ground is moved, and it is not packed into fewer places
    CHECK(
      mass[1] > 0.7 * mass[0] && mass[1] < 1.6 * mass[0],
      "creep changed the amount of erosion too much (mean change %.3f vs %.3f)",
      mass[1],
      mass[0]
    );
    CHECK(
      vs[1][2].cover > 0.9 * vs[0][2].cover,
      "the erosion is packed into fewer places with creep (cover %.2f vs %.2f)",
      vs[1][2].cover,
      vs[0][2].cover
    );
    // no grid direction: the fine change points as much along the diagonals and the axes as anywhere (a grid walk would
    // pile it up there)
    CHECK(
      vs[1][2].axes > 0.6 && vs[1][2].axes < 1.6 && vs[1][2].diagonals > 0.6 && vs[1][2].diagonals < 1.6,
      "the fine change prefers a grid direction (axes %.2f, diagonals %.2f)",
      vs[1][2].axes,
      vs[1][2].diagonals
    );
    // creep is a setting: more creep, smoother grooves; and its smoothing scales with the droplet count (twice the
    // droplets, twice the passes per round: the groove sharpness stays)
    {
      const GridPtr c1 = Make("erode_droplet", "density=2,seed=1,creep=1", {{"a", M}});
      const GridPtr c4 = Make("erode_droplet", "density=2,seed=1,creep=4", {{"a", M}});
      const GridPtr d4 = Make("erode_droplet", "density=4,seed=1,creep=2", {{"a", M}});
      const double a1 = MeasureVeins(*M, *c1).lap1, a4 = MeasureVeins(*M, *c4).lap1, ad = MeasureVeins(*M, *d4).lap1,
                   a2 = vs[1][0].lap1;
      std::printf(
        "veins creep 1 / 2 / 4: 1 cell Laplacian share %.3f %.3f %.3f; density 4 creep 2: %.3f\n", a1, a2, a4, ad
      );
      CHECK(a1 > a2 && a2 > a4, "more creep does not smooth the grooves more (%.3f %.3f %.3f)", a1, a2, a4);
      CHECK(
        ad < 2.0 * a2 + 0.02,
        "with twice the droplets the grooves get much sharper (%.3f vs %.3f): creep does not follow the density",
        ad,
        a2
      );
    }
    // the ground the droplets did not touch is not smoothed: a plain far from the mounds keeps its small scale detail
    // (the creep works on the change only)
    {
      const GridPtr P = Make("perlin", "width=97,height=97,seed=5,scale=6,octaves=2", {});
      const GridPtr S = Make("affine", "mul=0.6,add=30", {{"a", P}});
      const GridPtr r = Make("erode_droplet", "density=0.05,seed=1,creep=8", {{"a", S}});
      const double before = MeanAbsLaplacian(*S), after = MeanAbsLaplacian(*r);
      std::printf("veins creep leaves the input's own relief: fine relief %.4f -> %.4f\n", before, after);
      CHECK(after > 0.9 * before, "creep smoothed the input's own detail (%.4f -> %.4f)", before, after);
    }
    // creep 0 is the old solver: the golden `droplet_creep0` carries the checksum `droplet` had before creep existed
  }

  /** How much of the erosion of a smooth mountain lands on the crest, the upper and the lower flank (by height rank of
   * the input): the erosion has to cover the slopes, not only the crest area. */
  static void TestFlankShare()
  {
    SetThreads(4);
    const GridPtr M = Mounds(161);
    GridPtr cur = M;
    for (int pass = 0; pass < 3; ++pass)
      cur = Make("erode_droplet", ("density=2,seed=" + std::to_string(pass + 1)).c_str(), {{"a", cur}});
    // rank by height among the ground above 12% of the range (the mounds), crest = top 15%, upper flank = next 30%,
    // lower flank = the rest
    float lo = M->v[0], hi = M->v[0];
    for (const float x : M->v) {
      lo = std::min(lo, x);
      hi = std::max(hi, x);
    }
    std::vector<float> sel;
    for (const float x : M->v)
      if (x > lo + 0.12f * (hi - lo))
        sel.push_back(x);
    std::vector<float> sorted = sel;
    std::sort(sorted.begin(), sorted.end());
    const float t1 = sorted[static_cast<std::size_t>(0.55 * (sorted.size() - 1))],
                t2 = sorted[static_cast<std::size_t>(0.85 * (sorted.size() - 1))];
    double cut[3] = {}, area[3] = {}, tot = 0.0;
    for (std::size_t i = 0; i < M->v.size(); ++i) {
      if (!(M->v[i] > lo + 0.12f * (hi - lo)))
        continue;
      const int c = M->v[i] >= t2 ? 0 : (M->v[i] >= t1 ? 1 : 2);
      const double d = std::max(0.0, static_cast<double>(M->v[i]) - cur->v[i]);
      cut[c] += d;
      area[c] += 1.0;
      tot += d;
    }
    std::printf(
      "flank share after 3 passes: crest %.2f (of the area %.2f), upper flank %.2f (%.2f), lower flank %.2f (%.2f)\n",
      cut[0] / tot,
      area[0] / sel.size(),
      cut[1] / tot,
      area[1] / sel.size(),
      cut[2] / tot,
      area[2] / sel.size()
    );
    CHECK(cut[1] / tot + cut[2] / tot > 0.7, "the crest takes too much of the erosion (%.2f)", cut[0] / tot);
    CHECK(
      cut[2] / tot > 0.8 * area[2] / sel.size() * 0.5,
      "the lower flank is hardly eroded (share %.2f of the cut, %.2f of the area)",
      cut[2] / tot,
      area[2] / sel.size()
    );
  }

  static void Lab(
    const std::string& dir,
    const int n,
    const std::string& only,
    const std::string& extraParams
  )
  {
    const GridPtr H = LabTerrain(n, 60.0 * n / 513.0);
    const Stats hs = Measure(*H);
    std::printf("terrain %dx%d  min %.1f max %.1f mean %.1f sd %.1f\n", n, n, hs.min, hs.max, hs.mean, hs.sd);
    DumpRelief(dir + "/base.png", *H, hs.min, hs.max);
    for (const Preset& p : kPresets) {
      if (!only.empty() && only != p.name)
        continue;
      std::map<std::string, Grid> extra;
      const double t0 = Now();
      const GridPtr r = Make(
        p.op, (std::string(p.params) + (extraParams.empty() ? "" : "," + extraParams)).c_str(), {{"a", H}}, &extra
      );
      const double dt = Now() - t0;
      const Stats s = Measure(*r);
      std::printf(
        "%-10s %.3f s   min %.1f max %.1f mean %.2f sd %.2f   wear %.3g deposit %.3g\n",
        p.name,
        dt,
        s.min,
        s.max,
        s.mean,
        s.sd,
        Measure(extra["wear"]).mean,
        Measure(extra["deposit"]).mean
      );
      {
        std::size_t im = 0;
        for (std::size_t i = 0; i < r->v.size(); ++i)
          if (r->v[i] < r->v[im])
            im = i;
        const int mx = static_cast<int>(im % r->w), mz = static_cast<int>(im / r->w);
        std::printf("   lowest at (%d,%d) = %.2f, was %.2f%c", mx, mz, r->v[im], H->v[im], 10);
      }
      DumpRelief(dir + "/" + p.name + ".png", *r, hs.min, hs.max);
      DumpMask(dir + "/" + p.name + "_wear.png", extra["wear"]);
      DumpMask(dir + "/" + p.name + "_deposit.png", extra["deposit"]);
      DumpMask(dir + "/" + p.name + "_flow.png", extra["flow"], -1.0f, true);
    }
  }

  /** How well does a coarse run (every step-th sample, parameters scaled like erosion.lua's OpParams) predict the full
   * resolution run? Prints the correlation of the height changes. */
  static void ScaleStudy(
    const std::string& name,
    const int n,
    const int step,
    const std::string& extra
  )
  {
    const GridPtr H = LabTerrain(n, 60.0 * n / 513.0);
    const Preset* pr = nullptr;
    for (const Preset& p : kPresets)
      if (name == p.name)
        pr = &p;
    if (pr == nullptr) {
      std::printf("no such preset%c", 10);
      return;
    }
    const GridPtr full = Make(pr->op, pr->params, {{"a", H}});
    // coarse terrain
    const int cn = (n - 1) / step + 1;
    auto coarse = std::make_shared<Grid>(cn, cn, static_cast<float>(step), 0.0f, 0.0f);
    for (int z = 0; z < cn; ++z)
      for (int x = 0; x < cn; ++x)
        coarse->At(x, z) = H->At(x * step, z * step);
    std::string params = pr->params;
    // scaled parameters
    Params parsed;
    ParseParams(params, parsed);
    auto scaled = [&](const char* key, double def, double div, double lo) {
      const double v = parsed.num.count(key) ? parsed.num[key] : def;
      char b[64];
      std::snprintf(b, sizeof(b), ",%s=%g", key, std::max(lo, std::floor(v / div + 0.5)));
      params += b;
    };
    if (std::string(pr->op) == "erode_hydraulic")
      scaled("iterations", 200, step, 10);
    if (std::string(pr->op) == "erode_droplet") {
      scaled("lifetime", 30, step, 5);
      scaled("radius", 3, step, 1);
    }
    if (!extra.empty())
      params += "," + extra;
    const GridPtr cr = Make(pr->op, params, {{"a", coarse}});
    // coarse diff -> full resolution by bilinear resize
    auto diffc = std::make_shared<Grid>(*cr);
    for (std::size_t i = 0; i < diffc->v.size(); ++i)
      diffc->v[i] = cr->v[i] - coarse->v[i];
    const GridPtr up =
      Make("resize", ("width=" + std::to_string(n) + ",height=" + std::to_string(n)).c_str(), {{"a", diffc}});
    double sf = 0, su = 0, sff = 0, suu = 0, sfu = 0;
    const std::size_t cnt = H->v.size();
    for (std::size_t i = 0; i < cnt; ++i) {
      const double df = full->v[i] - H->v[i], du = up->v[i];
      sf += df;
      su += du;
      sff += df * df;
      suu += du * du;
      sfu += df * du;
    }
    const double mf = sf / cnt, mu = su / cnt;
    const double vf = sff / cnt - mf * mf, vu = suu / cnt - mu * mu, cv = sfu / cnt - mf * mu;
    std::printf(
      "scale study %s n=%d step=%d: full diff mean %.3f rms %.3f | coarse diff mean %.3f rms %.3f | correlation %.3f%c",
      pr->name,
      n,
      step,
      mf,
      std::sqrt(sff / cnt),
      mu,
      std::sqrt(suu / cnt),
      cv / std::sqrt(std::max(1e-12, vf * vu)),
      10
    );
  }

  TEST(
    Erosion,
    GoldenChecksums
  )
  {
    ASSERT_TRUE(LoadCases(FAF_EROSION_CASES)) << "cannot read " << FAF_EROSION_CASES;
    TestGoldens(false);
  }

  TEST(
    Erosion,
    Properties
  )
  {
    TestProperties();
  }

  TEST(
    Erosion,
    Boundary
  )
  {
    TestBoundary();
  }

  TEST(
    Erosion,
    BrushBoundary
  )
  {
    TestBrushBoundary();
  }

  TEST(
    Erosion,
    BrushQuality
  )
  {
    TestBrushQuality();
  }

  TEST(
    Erosion,
    Variation
  )
  {
    TestVariation();
  }

  TEST(
    Erosion,
    SolverExtras
  )
  {
    TestSolverExtras();
  }

  TEST(
    Erosion,
    FeedbackAndHierarchy
  )
  {
    TestFeedbackAndHierarchy();
  }

  TEST(
    Erosion,
    Veins
  )
  {
    TestVeins();
  }

  TEST(
    Erosion,
    FlankShare
  )
  {
    TestFlankShare();
  }

} // namespace
