// The terrain field library (src/editor/terrain/EdFieldCore.cpp, from FAF Studio): every golden case of
// tests/editor/data/field_cases.lua (Studio's selftest_fields_cases.lua) gives the same checksum at 1, 2, 3, 5 and
// 8 threads and the one in the file; properties of the core ops; a long pipeline independent of the thread count.
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

#include "editor/terrain/EdFieldCore.h"

#include <gtest/gtest.h>

using namespace faf::editor::field;

namespace
{

  static int gDefaultThreads = 1;
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

  // ---- param strings: k=v,k=v ; v is a number, a word, or a list a:b;c:d (flattened)
  // ------------------------------------------------------------------

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

  static bool ToNumber(
    const std::string& s,
    double& v
  )
  {
    if (s.empty())
      return false;
    char* end = nullptr;
    v = std::strtod(s.c_str(), &end);
    return end != nullptr && *end == '\0';
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
      const std::string key = kv.substr(0, eq);
      const std::string val = kv.substr(eq + 1);
      double n = 0.0;
      if (val.find(':') != std::string::npos || val.find(';') != std::string::npos) {
        std::vector<double> flat;
        for (const std::string& pt : Split(val, ';')) {
          for (const std::string& c : Split(pt, ':')) {
            if (ToNumber(c, n))
              flat.push_back(n);
          }
        }
        p.arr[key] = flat;
      } else if (ToNumber(val, n)) {
        p.num[key] = n;
      } else {
        p.str[key] = val;
      }
    }
  }

  static std::map<std::string, GridPtr> gFix;

  static GridPtr Make(
    const std::string& op,
    const std::string& params,
    const std::map<std::string, GridPtr>& in,
    std::string* err = nullptr
  )
  {
    OpArgs a;
    ParseParams(params, a.p);
    a.in = in;
    auto g = std::make_shared<Grid>();
    std::string e;
    if (!RunOp(op, a, *g, e)) {
      if (err)
        *err = e;
      else
        std::printf("op %s(%s) failed: %s\n", op.c_str(), params.c_str(), e.c_str());
      return nullptr;
    }
    return g;
  }

  static void BuildFixtures()
  {
    gFix.clear();
    gFix["A"] = Make("perlin", "width=33,height=33,seed=7,scale=12,octaves=4", {});
    gFix["H"] = Make("affine", "mul=40,add=10", {{"a", gFix["A"]}});
    gFix["M"] = Make("voronoi", "width=33,height=33,scale=10,seed=5", {});
    gFix["N"] = Make("perlin", "width=33,height=33,seed=9,scale=9,octaves=3", {});
  }

  struct Case
  {
    std::string label, op, params, inputs, golden;
  };

  static std::vector<std::string> gLines; // the whole cases file, to rewrite
  static std::vector<Case> gCases;
  static std::size_t gBegin = 0, gEnd = 0;

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

  // ---- tests
  // ------------------------------------------------------------------------------------------------------------------------------------------

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
        std::string err;
        const GridPtr g = Make(c.op, c.params, InputsOf(c.inputs), &err);
        if (!g) {
          CHECK(false, "case %s: %s", c.label.c_str(), err.c_str());
          if (tc == counts[0])
            now.push_back("0");
          continue;
        }
        const std::string hex = Hex(Checksum(*g));
        if (tc == counts[0]) {
          now.push_back(hex);
        } else {
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
      // rewrite the golden column
      std::size_t ci = 0;
      for (std::size_t i = gBegin; i < gEnd; ++i) {
        std::string& l = gLines[i];
        if (l.empty() || l[0] == '#')
          continue;
        std::vector<std::string> f = Split(l, '|');
        if (f.size() < 5)
          continue;
        f[4] = now[ci++];
        l = f[0] + "|" + f[1] + "|" + f[2] + "|" + f[3] + "|" + f[4];
      }
      std::printf("updated %d goldens\n", wrong);
    } else {
      CHECK(wrong == 0, "%d goldens differ (run with --update after checking the change is intended)", wrong);
    }
  }

  static GridPtr RunField(
    const char* op,
    const char* params,
    std::map<std::string, GridPtr> in = {}
  )
  {
    GridPtr g = Make(op, params, in);
    CHECK(g != nullptr, "op %s failed", op);
    return g ? g : std::make_shared<Grid>(1, 1, 1.0f, 0.0f, 0.0f);
  }

  static void TestThreadsLarge()
  {
    // a longer pipeline on a bigger grid: the result must not depend on the number of threads
    std::uint64_t first = 0;
    for (const int tc : {1, 2, 7}) {
      SetThreads(tc);
      const GridPtr n = RunField("perlin", "width=257,height=257,seed=3,scale=60,octaves=5");
      const GridPtr h = RunField("affine", "mul=60,add=0", {{"a", n}});
      const GridPtr b = RunField("blur", "radius=3", {{"a", h}});
      const GridPtr t = RunField("thermal", "iterations=12,talus=0.5", {{"a", b}});
      const GridPtr d = RunField("distance", "threshold=40", {{"a", t}});
      const GridPtr s = RunField("slope", "mode=rating,window=2", {{"a", t}});
      const GridPtr m = RunField("blend", "mode=overlay,opacity=0.7", {{"a", d}, {"b", s}});
      const std::uint64_t cs = Checksum(*m);
      if (tc == 1)
        first = cs;
      CHECK(cs == first, "pipeline differs with %d threads", tc);
    }
    SetThreads(gDefaultThreads);
  }

  static void TestProperties()
  {
    SetThreads(gDefaultThreads);
    BuildFixtures();

    // noise: in range, spread, not constant
    for (const char* op : {"perlin", "simplex", "ridged", "billow"}) {
      const GridPtr n = RunField(op, "width=129,height=129,seed=11,scale=30,octaves=4");
      const Stats s = Measure(*n);
      CHECK(s.min >= 0.0f && s.max <= 1.0f, "%s out of 0..1: %f %f", op, s.min, s.max);
      CHECK(s.sd > 0.03, "%s too flat: sd %f", op, s.sd);
      std::printf("  %s: min %.3f max %.3f mean %.3f sd %.3f\n", op, s.min, s.max, s.mean, s.sd);
    }
    // seeds differ, the same seed repeats, noise depends on the world position and not on the grid origin
    {
      const GridPtr a = RunField("perlin", "width=40,height=40,seed=1,scale=10");
      const GridPtr b = RunField("perlin", "width=40,height=40,seed=2,scale=10");
      const GridPtr c = RunField("perlin", "width=40,height=40,seed=1,scale=10");
      CHECK(Checksum(*a) != Checksum(*b), "seeds give the same field");
      CHECK(Checksum(*a) == Checksum(*c), "same seed differs");
      const GridPtr big = RunField("perlin", "width=60,height=60,seed=1,scale=10");
      const GridPtr part = RunField("crop", "x0=7,z0=5,x1=46,z1=44", {{"a", big}});
      const GridPtr shifted = RunField("perlin", "width=40,height=40,seed=1,scale=10,ox=7,oz=5");
      float maxd = 0;
      for (std::size_t i = 0; i < part->Count(); ++i)
        maxd = std::max(maxd, std::fabs(part->v[i] - shifted->v[i]));
      CHECK(maxd == 0.0f, "noise depends on the grid origin: %g", maxd);
      // a coarse preview samples the same noise: the value at world (8, 8) is the same on a 1 unit grid and on a 4 unit
      // grid
      const GridPtr coarse = RunField("perlin", "width=17,height=17,seed=1,scale=10,cell=4");
      const GridPtr fine = RunField("perlin", "width=65,height=65,seed=1,scale=10,cell=1");
      CHECK(coarse->At(2, 2) == fine->At(8, 8), "preview grid samples different noise");
    }
    // simplex range
    {
      float lo = 1e9f, hi = -1e9f;
      const GridPtr n = RunField("simplex", "width=1024,height=1024,seed=5,scale=7,octaves=1"); // 0.5 s + 0.5, clamped
      for (const float v : n->v) {
        lo = std::min(lo, v);
        hi = std::max(hi, v);
      }
      std::printf("  simplex single octave (0.5 s + 0.5, clamped): %.4f .. %.4f\n", lo, hi);
      CHECK(hi > 0.9f && lo < 0.1f, "simplex scale is off");
    }
    // const / invert / clamp / affine
    {
      const GridPtr c = RunField("const", "width=5,height=4,value=0.25");
      CHECK(c->w == 5 && c->h == 4 && c->v[7] == 0.25f, "const");
      const GridPtr inv = RunField("invert", "", {{"a", c}});
      CHECK(inv->v[3] == 0.75f, "invert");
      const GridPtr cl = RunField("clamp", "lo=0.3,hi=0.9", {{"a", c}});
      CHECK(cl->v[0] == 0.3f, "clamp");
    }
    // blur: a constant stays, spread falls
    {
      const GridPtr c = RunField("const", "width=30,height=30,value=0.6");
      const GridPtr b = RunField("blur", "radius=3", {{"a", c}});
      float maxd = 0;
      for (const float v : b->v)
        maxd = std::max(maxd, std::fabs(v - 0.6f));
      CHECK(maxd < 1e-5f, "blur of a constant moved by %g", maxd);
      const GridPtr n = gFix["N"];
      const GridPtr nb = RunField("blur", "radius=2", {{"a", n}});
      CHECK(Measure(*nb).sd < Measure(*n).sd, "blur did not reduce the spread");
      const GridPtr bx = RunField("box", "radius=2", {{"a", n}});
      CHECK(Measure(*bx).sd < Measure(*n).sd, "box did not reduce the spread");
    }
    // distance transform against brute force
    {
      const GridPtr base = RunField("white", "width=21,height=17,seed=4");
      const GridPtr d = RunField("distance", "threshold=0.93", {{"a", base}});
      bool any = false;
      float worst = 0;
      for (int z = 0; z < 17; ++z) {
        for (int x = 0; x < 21; ++x) {
          double best = 1e9;
          for (int zz = 0; zz < 17; ++zz) {
            for (int xx = 0; xx < 21; ++xx) {
              if (base->At(xx, zz) > 0.93f) {
                any = true;
                best = std::min(best, std::sqrt(double((x - xx) * (x - xx) + (z - zz) * (z - zz))));
              }
            }
          }
          if (best < 1e8)
            worst = std::max(worst, std::fabs(float(best) - d->At(x, z)));
        }
      }
      CHECK(any && worst < 1e-4f, "distance transform differs from brute force by %g", worst);
      const GridPtr sd = RunField("distance", "threshold=0.93,mode=signed", {{"a", base}});
      CHECK(sd->Count() == base->Count(), "signed distance");
    }
    // slope on a ramp: 0.5 units per sample
    {
      Grid ramp(16, 16, 1.0f, 0.0f, 0.0f);
      for (int z = 0; z < 16; ++z)
        for (int x = 0; x < 16; ++x)
          ramp.At(x, z) = 0.5f * float(x);
      auto r = std::make_shared<Grid>(ramp);
      const GridPtr deg = RunField("slope", "mode=degrees", {{"a", r}});
      CHECK(std::fabs(deg->At(8, 8) - 26.5651f) < 0.01f, "slope degrees %f", deg->At(8, 8));
      const GridPtr rating = RunField("slope", "mode=rating,window=1", {{"a", r}});
      CHECK(std::fabs(rating->At(8, 8) - 0.5f) < 1e-6f, "slope rating %f", rating->At(8, 8));
      const GridPtr rating3 = RunField("slope", "mode=rating,window=3", {{"a", r}});
      CHECK(std::fabs(rating3->At(4, 4) - 0.5f) < 1e-6f, "slope rating window 3");
      const GridPtr var = RunField("slope", "mode=variation,window=2", {{"a", r}});
      CHECK(std::fabs(var->At(4, 4) - 1.0f) < 1e-6f, "slope variation %f", var->At(4, 4));
      // a cell size of 4 makes the same rise per sample a quarter of the slope per world unit
      auto coarse = std::make_shared<Grid>(ramp);
      coarse->cell = 4.0f;
      const GridPtr cr = RunField("slope", "mode=rating", {{"a", coarse}});
      CHECK(std::fabs(cr->At(8, 8) - 0.125f) < 1e-6f, "rating with cell 4: %f", cr->At(8, 8));
    }
    // thermal: keeps the total, lowers the steepest slope, a flat field stays flat
    {
      const GridPtr h = gFix["H"];
      const GridPtr t = RunField("thermal", "iterations=40,talus=0.3,rate=0.5", {{"a", h}});
      const double before = Measure(*h).mean;
      const double after = Measure(*t).mean;
      CHECK(std::fabs(before - after) < 1e-4, "thermal changed the mean: %f -> %f", before, after);
      const GridPtr r0 = RunField("slope", "mode=rating", {{"a", h}});
      const GridPtr r1 = RunField("slope", "mode=rating", {{"a", t}});
      CHECK(
        Measure(*r1).max < Measure(*r0).max,
        "thermal did not lower the steepest slope: %f -> %f",
        Measure(*r0).max,
        Measure(*r1).max
      );
      const GridPtr flat = RunField("const", "width=20,height=20,value=7");
      const GridPtr tf = RunField("thermal", "iterations=10", {{"a", flat}});
      CHECK(Checksum(*tf) == Checksum(*flat), "thermal moved a flat field");
    }
    // mirror symmetries
    {
      const GridPtr h = gFix["H"];
      const int n = 33;
      const GridPtr mx = RunField("mirror", "mode=x", {{"a", h}});
      const GridPtr mz = RunField("mirror", "mode=z,side=1", {{"a", h}});
      const GridPtr mxz = RunField("mirror", "mode=xz", {{"a", h}});
      const GridPtr r2 = RunField("mirror", "mode=rot2", {{"a", h}});
      const GridPtr r2b = RunField("mirror", "mode=rot2,side=1", {{"a", h}});
      const GridPtr r4 = RunField("mirror", "mode=rot4", {{"a", h}});
      const GridPtr r4b = RunField("mirror", "mode=rot4,side=1", {{"a", h}});
      const GridPtr dg = RunField("mirror", "mode=diag", {{"a", h}});
      const GridPtr ad = RunField("mirror", "mode=adiag,side=1", {{"a", h}});
      int bad = 0;
      for (int z = 0; z < n; ++z) {
        for (int x = 0; x < n; ++x) {
          if (mx->At(x, z) != mx->At(n - 1 - x, z))
            ++bad;
          if (mz->At(x, z) != mz->At(x, n - 1 - z))
            ++bad;
          if (mxz->At(x, z) != mxz->At(n - 1 - x, z) || mxz->At(x, z) != mxz->At(x, n - 1 - z))
            ++bad;
          if (r2->At(x, z) != r2->At(n - 1 - x, n - 1 - z))
            ++bad;
          if (r2b->At(x, z) != r2b->At(n - 1 - x, n - 1 - z))
            ++bad;
          if (r4->At(x, z) != r4->At(n - 1 - z, x))
            ++bad; // a quarter turn
          if (r4b->At(x, z) != r4b->At(n - 1 - z, x))
            ++bad;
          if (dg->At(x, z) != dg->At(z, x))
            ++bad;
          if (ad->At(x, z) != ad->At(n - 1 - z, n - 1 - x))
            ++bad;
        }
      }
      CHECK(bad == 0, "%d symmetry violations", bad);
      CHECK(mx->At(3, 5) == h->At(3, 5) && mx->At(30, 5) == h->At(2, 5), "mirror x master half");
      CHECK(mz->At(4, 30) == h->At(4, 30), "mirror z side 1 master half");
    }
    // remap / levels / terrace
    {
      const GridPtr id = RunField("remap", "points=0:0;1:1,smooth=0", {{"a", gFix["A"]}});
      float maxd = 0;
      for (std::size_t i = 0; i < id->Count(); ++i)
        maxd = std::max(maxd, std::fabs(id->v[i] - gFix["A"]->v[i]));
      CHECK(maxd < 1e-6f, "identity remap moved values by %g", maxd);
      const GridPtr sm = RunField("remap", "points=0:0;0.3:0.1;0.7:0.9;1:1,smooth=1", {{"a", gFix["A"]}});
      CHECK(Measure(*sm).min >= -1e-5f && Measure(*sm).max <= 1.0f + 1e-5f, "monotone cubic overshoots");
      const GridPtr lv = RunField("levels", "in_lo=0.4,in_hi=0.8,out_lo=0,out_hi=1", {{"a", gFix["A"]}});
      CHECK(Measure(*lv).min == 0.0f, "levels");
      const GridPtr tr = RunField("terrace", "steps=4,sharpness=1", {{"a", gFix["A"]}});
      std::map<int, int> levels;
      for (const float v : tr->v)
        levels[int(std::floor(v * 4.0f * 1000.0f + 0.5f))]++;
      CHECK(levels.size() <= 6, "terrace made %d distinct levels", int(levels.size()));
    }
    // geometry: offset by whole samples, resize shapes, rotate by 0 is identity
    {
      const GridPtr a = gFix["A"];
      const GridPtr off = RunField("offset", "move_x=5,move_z=0", {{"a", a}});
      CHECK(off->At(10, 3) == a->At(5, 3) && off->At(2, 3) == a->At(30, 3), "offset wraps");
      const GridPtr rot = RunField("rotate", "angle=0", {{"a", a}});
      CHECK(Checksum(*rot) == Checksum(*a), "rotate by 0");
      const GridPtr rs = RunField("resize", "width=17,height=17", {{"a", a}});
      CHECK(
        rs->w == 17 && rs->cell == 2.0f && rs->At(16, 16) == a->At(32, 32) && rs->At(8, 8) == a->At(16, 16), "resize"
      );
      const GridPtr sc = RunField("scale", "factor=1", {{"a", a}});
      CHECK(Checksum(*sc) == Checksum(*a), "scale by 1");
    }
    // checksum: -0 equals +0, dimensions count
    {
      Grid p(2, 2, 1.0f, 0, 0, 0.0f);
      Grid q(2, 2, 1.0f, 0, 0, -0.0f);
      Grid r(4, 1, 1.0f, 0, 0, 0.0f);
      CHECK(Checksum(p) == Checksum(q), "checksum -0");
      CHECK(Checksum(p) != Checksum(r), "checksum dims");
    }
    // preview downsample of a constant
    {
      const GridPtr c = RunField("const", "width=33,height=33,value=2");
      std::vector<float> out;
      Downsample(*c, 8, 8, out);
      CHECK(out.size() == 64 && out[10] == 2.0f, "downsample");
    }
    // height_from_gradient: integrates the slopes of a smooth height back (lengths that are not powers of two use the
    // chirp-z transform)
    for (const bool periodic : {true, false}) {
      const int W = 100;
      const int H = 80;
      const double pi = 3.14159265358979323846;
      auto h0 = std::make_shared<Grid>(W, H, 2.0f, 0, 0, 0.0f);
      auto dx = std::make_shared<Grid>(W, H, 2.0f, 0, 0, 0.0f);
      auto dz = std::make_shared<Grid>(W, H, 2.0f, 0, 0, 0.0f);
      for (int z = 0; z < H; ++z) {
        for (int x = 0; x < W; ++x) {
          double v, px, pz;
          if (periodic) { // tiles: three periods across, two down
            const double ax = 2 * pi * 3 / W, az = 2 * pi * 2 / H;
            v = 10 * std::sin(ax * x) + 6 * std::cos(az * z) + 4 * std::sin(ax * x + az * z);
            px =
              (10 * ax * std::cos(ax * x) + 4 * ax * std::cos(ax * x + az * z)) / 2.0; // per world unit: the cell is 2
            pz = (-6 * az * std::sin(az * z) + 4 * az * std::cos(ax * x + az * z)) / 2.0;
          } else { // zero slope across the border
            const double ax = pi * 2 / (W - 1), az = pi * 3 / (H - 1);
            v = 10 * std::cos(ax * x) * std::cos(az * z) + 5 * std::cos(ax * x * 2);
            px = (-10 * ax * std::sin(ax * x) * std::cos(az * z) - 10 * ax * std::sin(ax * x * 2)) / 2.0;
            pz = (-10 * az * std::cos(ax * x) * std::sin(az * z)) / 2.0;
          }
          h0->At(x, z) = static_cast<float>(v); // the height in world units: the sum of slope * cell
          dx->At(x, z) = static_cast<float>(px);
          dz->At(x, z) = static_cast<float>(pz);
        }
      }
      std::string err;
      const GridPtr r =
        Make("height_from_gradient", periodic ? "periodic=1" : "periodic=0", {{"dx", dx}, {"dz", dz}}, &err);
      CHECK(r != nullptr && r->w == W && r->h == H, "height_from_gradient: %s", err.c_str());
      if (r) {
        double m0 = 0, m1 = 0, rms = 0, amp = 0;
        for (std::size_t i = 0; i < r->Count(); ++i) {
          m0 += h0->v[i];
          m1 += r->v[i];
        }
        m0 /= r->Count();
        m1 /= r->Count();
        for (std::size_t i = 0; i < r->Count(); ++i) {
          const double a = h0->v[i] - m0, b = r->v[i] - m1;
          rms += (a - b) * (a - b);
          amp += a * a;
        }
        const double rel = std::sqrt(rms / amp);
        std::printf(
          "  height_from_gradient %s: relative error %.4f (mean of result %.2g)\n",
          periodic ? "periodic" : "mirrored",
          rel,
          m1
        );
        CHECK(
          rel < 0.04 && std::fabs(m1) < 1.0e-3,
          "height_from_gradient %s: error %f mean %g",
          periodic ? "periodic" : "mirrored",
          rel,
          m1
        );
      }
    }
    // unknown op and missing input are errors, not crashes
    {
      std::string err;
      CHECK(Make("nope", "", {}, &err) == nullptr && !err.empty(), "unknown op");
      CHECK(Make("blur", "radius=2", {}, &err) == nullptr, "blur without input");
      CHECK(
        Make("add", "", {{"a", gFix["A"]}, {"b", RunField("const", "width=5,height=5")}}, &err) == nullptr,
        "add with mismatched sizes"
      );
      CHECK(OpNames().size() >= 35, "only %d ops", int(OpNames().size()));
    }
  }

  static double Now()
  {
    return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
  }

  static void Bench()
  {
    for (const int tc : {1, gDefaultThreads}) {
      SetThreads(tc);
      std::printf("bench, %d thread(s), 1025 x 1025:\n", tc);
      double t = Now();
      const GridPtr n = RunField("perlin", "width=1025,height=1025,seed=3,scale=120,octaves=5");
      std::printf("  perlin fBm 5 octaves   %8.1f ms\n", (Now() - t) * 1000);
      const GridPtr h = RunField("affine", "mul=60,add=0", {{"a", n}});
      t = Now();
      const GridPtr b = RunField("blur", "radius=4", {{"a", h}});
      std::printf("  gaussian blur sigma 4  %8.1f ms\n", (Now() - t) * 1000);
      t = Now();
      const GridPtr th = RunField("thermal", "iterations=50,talus=0.5", {{"a", h}});
      std::printf("  thermal 50 iterations  %8.1f ms\n", (Now() - t) * 1000);
      t = Now();
      const GridPtr d = RunField("distance", "threshold=30", {{"a", h}});
      std::printf("  distance field         %8.1f ms\n", (Now() - t) * 1000);
      t = Now();
      const GridPtr s = RunField("slope", "mode=rating,window=2", {{"a", h}});
      std::printf("  slope rating window 2  %8.1f ms\n", (Now() - t) * 1000);
      (void)b;
      (void)th;
      (void)d;
      (void)s;
    }
  }

  // The golden cases whose op this build has (the erosion ops come with the erosion library).
  void KeepKnownCases(
    int& skipped
  )
  {
    const std::vector<std::string> names = OpNames();
    std::vector<Case> kept;
    for (const Case& c : gCases) {
      if (std::find(names.begin(), names.end(), c.op) != names.end()) {
        kept.push_back(c);
      } else {
        ++skipped;
      }
    }
    gCases = kept;
  }

  TEST(
    Field,
    GoldenChecksumsAtEveryThreadCount
  )
  {
    gDefaultThreads = Threads();
    ASSERT_TRUE(LoadCases(FAF_FIELD_CASES)) << "cannot read " << FAF_FIELD_CASES;
    int skipped = 0;
    KeepKnownCases(skipped);
    std::printf("field goldens: %zu cases, %d skipped (op not built)\n", gCases.size(), skipped);
    ASSERT_FALSE(gCases.empty());
    TestGoldens(false);
  }

  TEST(
    Field,
    OpProperties
  )
  {
    gDefaultThreads = Threads();
    TestProperties();
  }

  TEST(
    Field,
    ResultDoesNotDependOnThreads
  )
  {
    TestThreadsLarge();
    SetThreads(gDefaultThreads);
  }
} // namespace
