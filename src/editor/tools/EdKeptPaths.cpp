#include "editor/tools/EdKeptPaths.h"

#include "editor/doc/EdJsonTree.h"
#include "editor/tools/EdMaskBrush.h"

#include <algorithm>
#include <cmath>
#include <memory>
#include <ranges>

namespace faf::editor
{
  namespace
  {
    constexpr float kStep = 1.0f;
    constexpr float kWord = 128.0f;

    float Lerp(
      const float a,
      const float b,
      const float t
    )
    {
      return a + (b - a) * t;
    }

    struct ModeInfo
    {
      const char* id;
      const char* label;
      bool offset;
      const char* clip;
      const char* preset;
      float h;
      const char* hLabel;
      bool interp;
      bool grade;
      bool river;
    };

    const ModeInfo& Info(
      const KeptPathMode mode
    )
    {
      static const ModeInfo kModes[kKeptPathModeCount] = {
        {"carve", "Carve", true, "none", "u", -6.0f, "Depth (negative cuts)", false, false, false},
        {"raise", "Raise", true, "none", "ridge", 6.0f, "Height (positive raises)", false, false, false},
        {"level", "Level", false, "none", "ramp", 0.0f, "Height above the ground", true, true, false},
        {"ramp", "Ramp", false, "none", "ramp", 0.0f, "Height above the ground", true, true, false},
        {"road", "Road", false, "none", "road", 0.0f, "Height above the ground", true, true, false},
        {"river", "River", false, "min", "u", 3.0f, "Depth below the water", false, false, true},
      };
      const int i = std::clamp(static_cast<int>(mode), 0, kKeptPathModeCount - 1);
      return kModes[i];
    }

    float Quarter(
      const float v
    )
    {
      return std::floor(v * 4.0f + 0.5f) / 4.0f;
    }

    /** Studio's Pin: a target-mode path pins its first point at the ground, the newest point is the pinned end. */
    void Pin(
      KeptPath& path,
      const std::function<float(float, float)>& ground
    )
    {
      const ModeInfo& m = Info(path.mode);
      const int n = static_cast<int>(path.points.size());
      if (!m.interp || n == 0) {
        return;
      }
      KeptPathPoint& first = path.points.front();
      if (n == 1) {
        first.abs = true;
        first.autoPin = true;
        first.h = Quarter(ground(first.x, first.z));
        return;
      }
      for (int i = 1; i < n - 1; ++i) {
        KeptPathPoint& p = path.points[static_cast<std::size_t>(i)];
        if (p.autoPin) {
          p.autoPin = false;
          p.abs = false;
          p.h = 0.0f;
        }
      }
      KeptPathPoint& last = path.points.back();
      if (!last.abs || last.autoPin) {
        last.abs = true;
        last.autoPin = true;
        last.h = path.mode == KeptPathMode::Level ? first.h : Quarter(ground(last.x, last.z));
      }
    }

    float Clamp(
      const float v,
      const float lo,
      const float hi
    )
    {
      return v < lo ? lo : (v > hi ? hi : v);
    }

    std::shared_ptr<field::Grid> Shared(
      field::Grid g
    )
    {
      return std::make_shared<field::Grid>(std::move(g));
    }

    void ProfileParams(
      const KeptPath& path,
      field::Params& p
    )
    {
      std::vector<double> flat;
      for (const auto& q : path.profile.points) {
        flat.push_back(q[0]);
        flat.push_back(q[1]);
      }
      p.arr["profile"] = std::move(flat);
      p.num["smooth"] = path.profile.smooth ? 1.0 : 0.0;
      p.num["symmetric"] = path.profile.symmetric ? 1.0 : 0.0;
    }

    std::vector<double> FlatPts(
      const KeptPathSamples& S,
      const std::vector<float>& ys,
      const std::vector<float>& offs
    )
    {
      std::vector<double> flat;
      flat.reserve(S.Count() * 8);
      for (std::size_t k = 0; k < S.Count(); ++k) {
        flat.push_back(S.x[k]);
        flat.push_back(S.z[k]);
        flat.push_back(k < ys.size() ? ys[k] : 0.0f);
        flat.push_back(S.w[k]);
        flat.push_back(S.f[k]);
        flat.push_back(S.bank[k]);
        flat.push_back(k < offs.size() ? offs[k] : 0.0f);
        flat.push_back(S.s[k]);
      }
      return flat;
    }

    float HashFloat(
      std::uint32_t& state
    )
    {
      // Studio's Lcg: Park-Miller.
      state = static_cast<std::uint32_t>((static_cast<std::uint64_t>(state) * 16807ULL) % 2147483647ULL);
      return static_cast<float>(state) / 2147483647.0f;
    }
  } // namespace

  const char* KeptPathModeName(
    const KeptPathMode mode
  ) noexcept
  {
    return Info(mode).label;
  }

  const char* KeptPathModeId(
    const KeptPathMode mode
  ) noexcept
  {
    return Info(mode).id;
  }

  bool KeptPathModeFromId(
    const std::string& id,
    KeptPathMode& out
  )
  {
    for (int m = 0; m < kKeptPathModeCount; ++m) {
      if (id == Info(static_cast<KeptPathMode>(m)).id) {
        out = static_cast<KeptPathMode>(m);
        return true;
      }
    }
    return false;
  }

  const char* KeptPathHeightLabel(
    const KeptPathMode mode
  ) noexcept
  {
    return Info(mode).hLabel;
  }

  bool KeptPathOffsetMode(
    const KeptPathMode mode
  ) noexcept
  {
    return Info(mode).offset;
  }

  const std::vector<KeptPathProfilePreset>& KeptPathProfilePresets()
  {
    static const std::vector<KeptPathProfilePreset> kPresets = {
      {"ramp", "Ramp", true, {{0.0f, 1.0f}, {1.0f, 1.0f}}},
      {"road", "Road + shoulders", true, {{0.0f, 1.0f}, {0.6f, 1.0f}, {0.8f, 0.55f}, {1.0f, 0.2f}}},
      {"v", "V valley", false, {{0.0f, 1.0f}, {1.0f, 0.0f}}},
      {"u", "U canyon", true, {{0.0f, 1.0f}, {0.55f, 1.0f}, {0.8f, 0.85f}, {0.93f, 0.35f}, {1.0f, 0.0f}}},
      {"ridge", "Ridge", true, {{0.0f, 1.0f}, {0.4f, 0.45f}, {1.0f, 0.0f}}},
      {"wall", "Wall", true, {{0.0f, 1.0f}, {0.85f, 1.0f}, {1.0f, 0.0f}}},
      {"terrace",
       "Terrace steps",
       true,
       {{0.0f, 1.0f},
        {0.2f, 1.0f},
        {0.28f, 0.75f},
        {0.46f, 0.75f},
        {0.54f, 0.5f},
        {0.72f, 0.5f},
        {0.8f, 0.25f},
        {0.95f, 0.25f},
        {1.0f, 0.0f}}},
    };
    return kPresets;
  }

  const KeptPathProfilePreset& KeptPathProfilePresetOf(
    const std::string& id
  )
  {
    for (const KeptPathProfilePreset& p : KeptPathProfilePresets()) {
      if (id == p.id) {
        return p;
      }
    }
    return KeptPathProfilePresets().front();
  }

  float EvalKeptPathProfile(
    const KeptPathProfile& profile,
    const float x
  )
  {
    const auto& p = profile.points;
    const int n = static_cast<int>(p.size());
    if (n == 0) {
      return 1.0f;
    }
    if (n == 1 || x <= p[0][0]) {
      return p[0][1];
    }
    if (x >= p[static_cast<std::size_t>(n - 1)][0]) {
      return p[static_cast<std::size_t>(n - 1)][1];
    }
    int k = 0;
    while (k + 2 <= n - 1 && x >= p[static_cast<std::size_t>(k + 1)][0]) {
      ++k;
    }
    const auto P = [&](const int i) -> const std::array<float, 2>& {
      return p[static_cast<std::size_t>(i)];
    };
    const float x0 = P(k)[0];
    const float y0 = P(k)[1];
    const float x1 = P(k + 1)[0];
    const float y1 = P(k + 1)[1];
    const float h = x1 - x0;
    const float t = h > 0.0f ? (x - x0) / h : 0.0f;
    if (!profile.smooth) {
      return y0 + (y1 - y0) * t;
    }
    const auto delta = [&](const int i) {
      const float dx = P(i + 1)[0] - P(i)[0];
      return dx != 0.0f ? (P(i + 1)[1] - P(i)[1]) / dx : 0.0f;
    };
    const auto slope = [&](const int i) {
      if (i == 0) {
        return delta(0);
      }
      if (i == n - 1) {
        return delta(n - 2);
      }
      const float d0 = delta(i - 1);
      const float d1 = delta(i);
      if (d0 * d1 <= 0.0f) {
        return 0.0f;
      }
      const float h0 = P(i)[0] - P(i - 1)[0];
      const float h1 = P(i + 1)[0] - P(i)[0];
      const float w1 = 2.0f * h1 + h0;
      const float w2 = h1 + 2.0f * h0;
      return (w1 + w2) / (w1 / d0 + w2 / d1);
    };
    const float m0 = slope(k);
    const float m1 = slope(k + 1);
    const float t2 = t * t;
    const float t3 = t2 * t;
    return (2.0f * t3 - 3.0f * t2 + 1.0f) * y0 + (t3 - 2.0f * t2 + t) * h * m0 + (-2.0f * t3 + 3.0f * t2) * y1 +
      (t3 - t2) * h * m1;
  }

  const char* KeptStrataKindName(
    const KeptStrataKind kind
  ) noexcept
  {
    switch (kind) {
    case KeptStrataKind::Core:
      return "Core";
    case KeptStrataKind::Bank:
      return "Bank";
    case KeptStrataKind::Reach:
      return "Reach";
    }
    return "?";
  }

  const char* KeptScatterSideName(
    const KeptScatterSide side
  ) noexcept
  {
    switch (side) {
    case KeptScatterSide::Both:
      return "Both sides";
    case KeptScatterSide::Left:
      return "Left";
    case KeptScatterSide::Right:
      return "Right";
    case KeptScatterSide::Center:
      return "On the line";
    }
    return "?";
  }

  KeptPath NewKeptPath(
    const KeptPathMode mode,
    const bool bezier,
    const std::string& id
  )
  {
    KeptPath path;
    path.id = id;
    path.mode = mode;
    path.bezier = bezier;
    std::string number = id;
    if (!number.empty() && number[0] == 'p') {
      number = number.substr(1);
    }
    path.name = std::string(Info(mode).label) + " " + number;
    path.decals.spacing = 12.0f;
    path.decals.side = KeptScatterSide::Center;
    path.decals.lateral = 0.0f;
    path.decals.jitter = 0.2f;
    path.decals.scaleMin = 1.0f;
    path.decals.scaleMax = 1.0f;
    UseKeptPathPreset(path, Info(mode).preset);
    return path;
  }

  void UseKeptPathPreset(
    KeptPath& path,
    const std::string& presetId
  )
  {
    const KeptPathProfilePreset& pr = KeptPathProfilePresetOf(presetId);
    path.profile.points = pr.points;
    path.profile.smooth = pr.smooth;
    path.profile.symmetric = true;
    path.profile.preset = pr.id;
  }

  void SetKeptPathMode(
    KeptPath& path,
    const KeptPathMode mode,
    const std::function<float(float, float)>& ground
  )
  {
    const ModeInfo& old = Info(path.mode);
    const ModeInfo& m = Info(mode);
    path.mode = mode;
    UseKeptPathPreset(path, m.preset);
    if (old.offset != m.offset || old.river != m.river) {
      for (KeptPathPoint& p : path.points) {
        p.h = m.h;
        p.abs = false;
        p.autoPin = false;
      }
    } else if (m.offset) {
      // carve <-> raise: the amount keeps its size, the sign follows the mode
      for (KeptPathPoint& p : path.points) {
        p.h = mode == KeptPathMode::Raise ? std::abs(p.h) : -std::abs(p.h);
      }
    }
    Pin(path, ground);
  }

  void AddKeptPathPoint(
    KeptPath& path,
    const float x,
    const float z,
    const std::function<float(float, float)>& ground
  )
  {
    KeptPathPoint p;
    p.x = x;
    p.z = z;
    if (!path.points.empty()) {
      const KeptPathPoint& last = path.points.back();
      p.w = last.w;
      p.f = last.f;
      p.h = last.abs ? 0.0f : last.h;
      p.bank = 0.0f;
    } else {
      p.h = Info(path.mode).h;
    }
    path.points.push_back(p);
    Pin(path, ground);
  }

  void InsertKeptPathPoint(
    KeptPath& path,
    const int after,
    const float x,
    const float z
  )
  {
    const int n = static_cast<int>(path.points.size());
    if (after < 0 || after >= n) {
      return;
    }
    const KeptPathPoint& a = path.points[static_cast<std::size_t>(after)];
    const KeptPathPoint& b = path.points[static_cast<std::size_t>(after + 1 < n ? after + 1 : 0)];
    KeptPathPoint p = a;
    p.x = x;
    p.z = z;
    p.hasHo = p.hasHi = false;
    p.autoPin = false;
    const float d1 = std::hypot(x - a.x, z - a.z);
    const float d2 = std::hypot(x - b.x, z - b.z);
    const float t = d1 + d2 > 0.0f ? d1 / (d1 + d2) : 0.5f;
    p.w = Lerp(a.w, b.w, t);
    p.f = Lerp(a.f, b.f, t);
    p.h = Lerp(a.h, b.h, t);
    p.bank = Lerp(a.bank, b.bank, t);
    p.abs = false;
    path.points.insert(path.points.begin() + after + 1, p);
  }

  void PinKeptPathPoint(
    KeptPathPoint& p,
    const bool on,
    const std::function<float(float, float)>& ground
  )
  {
    if (on && !p.abs) {
      p.h = Quarter(ground(p.x, p.z));
    } else if (!on && p.abs) {
      p.h = 0.0f;
    }
    p.abs = on;
    p.autoPin = false;
  }

  KeptPath* KeptPathSet::Find(
    const std::string& id
  )
  {
    for (KeptPath& p : paths) {
      if (p.id == id) {
        return &p;
      }
    }
    return nullptr;
  }

  const KeptPath* KeptPathSet::Find(
    const std::string& id
  ) const
  {
    for (const KeptPath& p : paths) {
      if (p.id == id) {
        return &p;
      }
    }
    return nullptr;
  }

  std::string KeptPathSet::TakeId()
  {
    for (;;) {
      std::string id = "p" + std::to_string(nextId++);
      if (Find(id) == nullptr) {
        return id;
      }
    }
  }

  bool KeptPathSet::operator==(
    const KeptPathSet& other
  ) const
  {
    return KeptPathsText(*this) == KeptPathsText(other);
  }

  void KeptPathHandles(
    const KeptPath& path,
    std::vector<std::array<float, 2>>& out,
    std::vector<std::array<float, 2>>& in
  )
  {
    const auto& pts = path.points;
    const int n = static_cast<int>(pts.size());
    out.assign(static_cast<std::size_t>(n), {0.0f, 0.0f});
    in.assign(static_cast<std::size_t>(n), {0.0f, 0.0f});
    for (int i = 0; i < n; ++i) {
      const KeptPathPoint& p = pts[static_cast<std::size_t>(i)];
      const KeptPathPoint* prev =
        i > 0 ? &pts[static_cast<std::size_t>(i - 1)] : (path.closed && n > 2 ? &pts.back() : nullptr);
      const KeptPathPoint* next =
        i < n - 1 ? &pts[static_cast<std::size_t>(i + 1)] : (path.closed && n > 2 ? &pts.front() : nullptr);
      std::array<float, 2> ho{0.0f, 0.0f};
      std::array<float, 2> hi{0.0f, 0.0f};
      if (path.bezier && (p.hasHo || p.hasHi)) {
        ho = {p.ho[0], p.ho[1]};
        hi = {p.hi[0], p.hi[1]};
        if (!p.hasHi) {
          hi = {-ho[0], -ho[1]};
        }
        if (!p.hasHo) {
          ho = {-hi[0], -hi[1]};
        }
      } else if (path.bezier) {
        const float px = prev != nullptr ? prev->x : p.x;
        const float pz = prev != nullptr ? prev->z : p.z;
        const float qx = next != nullptr ? next->x : p.x;
        const float qz = next != nullptr ? next->z : p.z;
        float dx = qx - px;
        float dz = qz - pz;
        const float dl = std::hypot(dx, dz);
        if (dl > 0.0001f) {
          dx /= dl;
          dz /= dl;
        } else {
          dx = dz = 0.0f;
        }
        const float lo = next != nullptr ? std::hypot(next->x - p.x, next->z - p.z) / 3.0f : 0.0f;
        const float li = prev != nullptr ? std::hypot(p.x - prev->x, p.z - prev->z) / 3.0f : 0.0f;
        const float t = path.tension;
        ho = {dx * lo * t, dz * lo * t};
        hi = {-dx * li * t, -dz * li * t};
      } else {
        const float px = prev != nullptr ? prev->x : p.x;
        const float pz = prev != nullptr ? prev->z : p.z;
        const float qx = next != nullptr ? next->x : p.x;
        const float qz = next != nullptr ? next->z : p.z;
        const float t = path.tension / 6.0f;
        ho = {(qx - px) * t, (qz - pz) * t};
        hi = {-(qx - px) * t, -(qz - pz) * t};
      }
      out[static_cast<std::size_t>(i)] = ho;
      in[static_cast<std::size_t>(i)] = hi;
    }
  }

  KeptPathSamples SampleKeptPath(
    const KeptPath& path,
    const float step
  )
  {
    KeptPathSamples S;
    const auto& pts = path.points;
    const int n = static_cast<int>(pts.size());
    if (n == 0) {
      return S;
    }
    std::vector<std::array<float, 2>> out;
    std::vector<std::array<float, 2>> in;
    KeptPathHandles(path, out, in);
    const int nseg = path.closed && n > 2 ? n : n - 1;
    float len = 0.0f;
    const auto push =
      [&](const float x, const float z, const KeptPathPoint& a, const KeptPathPoint& b, const float t, const int seg) {
      if (!S.x.empty()) {
        len += std::hypot(x - S.x.back(), z - S.z.back());
      }
      S.x.push_back(x);
      S.z.push_back(z);
      S.w.push_back(Lerp(a.w, b.w, t));
      S.f.push_back(Lerp(a.f, b.f, t));
      S.bank.push_back(Lerp(a.bank, b.bank, t));
      S.h.push_back(Lerp(a.h, b.h, t));
      S.seg.push_back(seg);
      S.t.push_back(t);
      S.s.push_back(len);
    };
    if (nseg < 1) {
      push(pts[0].x, pts[0].z, pts[0], pts[0], 0.0f, 0);
      S.ctrlS.push_back(0.0f);
      return S;
    }
    S.ctrlS.assign(static_cast<std::size_t>(nseg + 1), 0.0f);
    for (int i = 0; i < nseg; ++i) {
      const int j = (i + 1) % n;
      const KeptPathPoint& a = pts[static_cast<std::size_t>(i)];
      const KeptPathPoint& b = pts[static_cast<std::size_t>(j)];
      const float p0x = a.x;
      const float p0z = a.z;
      const float p1x = a.x + out[static_cast<std::size_t>(i)][0];
      const float p1z = a.z + out[static_cast<std::size_t>(i)][1];
      const float p2x = b.x + in[static_cast<std::size_t>(j)][0];
      const float p2z = b.z + in[static_cast<std::size_t>(j)][1];
      const float p3x = b.x;
      const float p3z = b.z;
      const float poly =
        std::hypot(p1x - p0x, p1z - p0z) + std::hypot(p2x - p1x, p2z - p1z) + std::hypot(p3x - p2x, p3z - p2z);
      const int count = static_cast<int>(Clamp(std::ceil(poly / std::max(step, 0.05f)), 2.0f, 400.0f));
      const int last = i == nseg - 1 ? count : count - 1;
      // Positions first: the attributes run along the arc length of the segment.
      std::vector<float> qx(static_cast<std::size_t>(count + 1));
      std::vector<float> qz(static_cast<std::size_t>(count + 1));
      std::vector<float> cum(static_cast<std::size_t>(count + 1));
      float total = 0.0f;
      for (int q = 0; q <= count; ++q) {
        const float t = static_cast<float>(q) / static_cast<float>(count);
        const float u = 1.0f - t;
        const float c0 = u * u * u;
        const float c1 = 3.0f * u * u * t;
        const float c2 = 3.0f * u * t * t;
        const float c3 = t * t * t;
        qx[static_cast<std::size_t>(q)] = c0 * p0x + c1 * p1x + c2 * p2x + c3 * p3x;
        qz[static_cast<std::size_t>(q)] = c0 * p0z + c1 * p1z + c2 * p2z + c3 * p3z;
        if (q > 0) {
          total += std::hypot(
            qx[static_cast<std::size_t>(q)] - qx[static_cast<std::size_t>(q - 1)],
            qz[static_cast<std::size_t>(q)] - qz[static_cast<std::size_t>(q - 1)]
          );
        }
        cum[static_cast<std::size_t>(q)] = total;
      }
      for (int q = 0; q <= last; ++q) {
        float frac = total > 0.00001f ? cum[static_cast<std::size_t>(q)] / total
                                      : static_cast<float>(q) / static_cast<float>(count);
        if (q == count) {
          frac = 1.0f;
        }
        push(qx[static_cast<std::size_t>(q)], qz[static_cast<std::size_t>(q)], a, b, frac, i);
        if (q == 0) {
          S.ctrlS[static_cast<std::size_t>(i)] = len;
        }
      }
    }
    S.ctrlS[static_cast<std::size_t>(nseg)] = len;
    return S;
  }

  float KeptPathLength(
    const KeptPath& path
  )
  {
    const KeptPathSamples S = SampleKeptPath(path, 2.0f);
    return S.s.empty() ? 0.0f : S.s.back();
  }

  void KeptPathHeights(
    const KeptPath& path,
    const KeptPathSamples& S,
    const std::function<float(float, float)>& ground,
    const float water,
    std::vector<float>& ys,
    std::vector<float>& offs
  )
  {
    const ModeInfo& m = Info(path.mode);
    const std::size_t n = S.Count();
    ys.assign(n, 0.0f);
    offs.assign(n, 0.0f);
    if (m.offset) {
      offs = S.h;
      return;
    }
    const auto& pts = path.points;
    const int pc = static_cast<int>(pts.size());
    if (pc == 0) {
      return;
    }
    std::vector<float> yc(static_cast<std::size_t>(pc), 0.0f);
    std::vector<bool> pinned(static_cast<std::size_t>(pc), false);
    for (int i = 0; i < pc; ++i) {
      const KeptPathPoint& p = pts[static_cast<std::size_t>(i)];
      if (p.abs) {
        yc[static_cast<std::size_t>(i)] = p.h;
        pinned[static_cast<std::size_t>(i)] = true;
      } else if (m.river) {
        yc[static_cast<std::size_t>(i)] = water - p.h;
      } else {
        yc[static_cast<std::size_t>(i)] = ground(p.x, p.z) + p.h;
      }
    }
    if (m.interp && path.interp) {
      int lastPin = -1;
      for (int i = 0; i < pc; ++i) {
        if (!pinned[static_cast<std::size_t>(i)]) {
          continue;
        }
        if (lastPin >= 0 && i - lastPin > 1) {
          const float s0 =
            static_cast<std::size_t>(lastPin) < S.ctrlS.size() ? S.ctrlS[static_cast<std::size_t>(lastPin)] : 0.0f;
          const float s1 = static_cast<std::size_t>(i) < S.ctrlS.size() ? S.ctrlS[static_cast<std::size_t>(i)] : 0.0f;
          for (int j = lastPin + 1; j < i; ++j) {
            const float sj = static_cast<std::size_t>(j) < S.ctrlS.size() ? S.ctrlS[static_cast<std::size_t>(j)] : 0.0f;
            const float t = s1 > s0 ? (sj - s0) / (s1 - s0) : 0.0f;
            yc[static_cast<std::size_t>(j)] =
              Lerp(yc[static_cast<std::size_t>(lastPin)], yc[static_cast<std::size_t>(i)], t) +
              pts[static_cast<std::size_t>(j)].h;
          }
        }
        lastPin = i;
      }
    }
    std::vector<bool> pin(n, false);
    for (std::size_t k = 0; k < n; ++k) {
      const int a = S.seg[k];
      const int b = (a + 1) % pc;
      ys[k] = Lerp(yc[static_cast<std::size_t>(a)], yc[static_cast<std::size_t>(b)], S.t[k]);
      pin[k] = (S.t[k] == 0.0f && pinned[static_cast<std::size_t>(a)]) ||
        (S.t[k] == 1.0f && pinned[static_cast<std::size_t>(b)]);
    }
    if (path.limitGrade && m.grade && n > 1) {
      const float g = path.grade;
      for (int pass = 0; pass < 3; ++pass) {
        for (std::size_t k = 1; k < n; ++k) {
          if (!pin[k]) {
            const float ds = S.s[k] - S.s[k - 1];
            ys[k] = Clamp(ys[k], ys[k - 1] - g * ds, ys[k - 1] + g * ds);
          }
        }
        for (std::size_t k = n - 1; k-- > 0;) {
          if (!pin[k]) {
            const float ds = S.s[k + 1] - S.s[k];
            ys[k] = Clamp(ys[k], ys[k + 1] - g * ds, ys[k + 1] + g * ds);
          }
        }
      }
    }
    if (m.river) {
      for (std::size_t k = 1; k < n; ++k) {
        ys[k] = std::min(ys[k], ys[k - 1]);
      }
    }
  }

  KeptPathReport ReportKeptPath(
    const KeptPath& path,
    const std::function<float(float, float)>& ground,
    const float water
  )
  {
    KeptPathReport rep;
    const KeptPathSamples S = SampleKeptPath(path, kStep);
    const std::size_t n = S.Count();
    if (n < 2) {
      return rep;
    }
    std::vector<float> offs;
    KeptPathHeights(path, S, ground, water, rep.ys, offs);
    if (Info(path.mode).offset) {
      for (std::size_t k = 0; k < n; ++k) {
        rep.ys[k] = ground(S.x[k], S.z[k]) + S.h[k];
      }
    }
    const float limit = path.grade;
    double total = 0.0;
    double bad = 0.0;
    std::size_t k = 0;
    while (k + 1 < n) {
      std::size_t j = k + 1;
      while (j + 1 < n && S.s[j] - S.s[k] < 3.0f) {
        ++j;
      }
      const float ds = S.s[j] - S.s[k];
      const float g = ds > 0.01f ? std::abs(rep.ys[j] - rep.ys[k]) / ds : 0.0f;
      if (g > rep.max) {
        rep.max = g;
        rep.worstX = S.x[k];
        rep.worstZ = S.z[k];
      }
      total += ds;
      if (g > limit + 0.0001f) {
        bad += ds;
        if (!rep.flagged.empty() && rep.flagged.back().second >= static_cast<int>(k)) {
          rep.flagged.back().second = static_cast<int>(j);
        } else {
          rep.flagged.emplace_back(static_cast<int>(k), static_cast<int>(j));
        }
      }
      k = j;
    }
    rep.over = total > 0.0 ? static_cast<float>(bad / total) : 0.0f;
    return rep;
  }

  std::vector<KeptPathItem> KeptPathScatterPlan(
    const KeptPath& path,
    const KeptPathScatter& cfg
  )
  {
    std::vector<KeptPathItem> items;
    const KeptPathSamples S = SampleKeptPath(path, kStep);
    const std::size_t n = S.Count();
    if (n < 2 || !cfg.on) {
      return items;
    }
    std::uint32_t state = static_cast<std::uint32_t>((static_cast<std::int64_t>(cfg.seed) * 7919 + 12345) % 2147483647);
    if (state == 0) {
      state = 1;
    }
    const float spacing = std::max(0.5f, cfg.spacing);
    const float total = S.s.back();
    float d = spacing / 2.0f;
    std::size_t k = 0;
    while (d < total && items.size() < 4000) {
      while (k + 1 < n && S.s[k + 1] < d) {
        ++k;
      }
      const std::size_t j = std::min(n - 1, k + 1);
      const float ds = S.s[j] - S.s[k];
      const float t = ds > 0.0001f ? (d - S.s[k]) / ds : 0.0f;
      const float x = Lerp(S.x[k], S.x[j], t);
      const float z = Lerp(S.z[k], S.z[j], t);
      const float dx = S.x[j] - S.x[k];
      const float dz = S.z[j] - S.z[k];
      const float dl = std::hypot(dx, dz);
      float nx = 0.0f;
      float nz = 0.0f;
      if (dl > 0.0001f) {
        nx = -dz / dl;
        nz = dx / dl;
      }
      const float w = Lerp(S.w[k], S.w[j], t);
      int sides[2] = {0, 0};
      int count = 1;
      switch (cfg.side) {
      case KeptScatterSide::Both:
        sides[0] = -1;
        sides[1] = 1;
        count = 2;
        break;
      case KeptScatterSide::Left:
        sides[0] = -1;
        break;
      case KeptScatterSide::Right:
        sides[0] = 1;
        break;
      case KeptScatterSide::Center:
        sides[0] = 0;
        break;
      }
      for (int c = 0; c < count; ++c) {
        const int sd = sides[c];
        const float lat = sd == 0 ? 0.0f : static_cast<float>(sd) * (w + cfg.lateral);
        const float jx = (HashFloat(state) - 0.5f) * 2.0f * cfg.jitter;
        const float jz = (HashFloat(state) - 0.5f) * 2.0f * cfg.jitter;
        KeptPathItem item;
        item.x = x + nx * lat + jx;
        item.z = z + nz * lat + jz;
        item.heading = HashFloat(state) * 6.2831853f;
        item.scale = cfg.scaleMin + (cfg.scaleMax - cfg.scaleMin) * HashFloat(state);
        items.push_back(item);
      }
      d += spacing;
    }
    return items;
  }

  KeptPath KeptPathImageOf(
    const KeptPath& path,
    const KeptPathImage& image
  )
  {
    KeptPath c = path;
    for (KeptPathPoint& p : c.points) {
      const float x = p.x;
      const float z = p.z;
      image.map(x, z, p.x, p.z);
      const auto moveHandle = [&](float (&h)[2]) {
        float ax = 0.0f;
        float az = 0.0f;
        float bx = 0.0f;
        float bz = 0.0f;
        image.map(x, z, ax, az);
        image.map(x + h[0], z + h[1], bx, bz);
        h[0] = bx - ax;
        h[1] = bz - az;
      };
      if (p.hasHo) {
        moveHandle(p.ho);
      }
      if (p.hasHi) {
        moveHandle(p.hi);
      }
      if (image.mirror) {
        p.bank = -p.bank;
      }
    }
    if (image.mirror && !c.profile.symmetric) {
      std::vector<std::array<float, 2>> flipped;
      for (auto& entry : c.profile.points | std::views::reverse) {
        flipped.push_back({1.0f - entry[0], entry[1]});
      }
      c.profile.points = std::move(flipped);
    }
    return c;
  }

  std::expected<KeptPathPlan, std::string> BuildKeptPath(
    const KeptPath& path,
    const KeptPathGround& G,
    const KeptPathResult* old,
    const bool wantMasks
  )
  {
    KeptPathPlan plan;
    if (G.words == nullptr || G.width < 2 || G.height < 2) {
      return std::unexpected("no map");
    }
    if (path.points.empty()) {
      return std::unexpected("the path has no points");
    }
    // The path and its symmetry images, sampled.
    std::vector<KeptPath> set{path};
    if (path.sym) {
      for (const KeptPathImage& image : G.images) {
        set.push_back(KeptPathImageOf(path, image));
      }
    }
    auto samples = set | std::views::transform([&](const KeptPath& p) {
      return SampleKeptPath(p, kStep);
    }) |
      std::ranges::to<std::vector<KeptPathSamples>>();
    const float blend = Clamp(path.blend, 0.0f, 80.0f);
    float bx0 = 1e9f;
    float bz0 = 1e9f;
    float bx1 = -1e9f;
    float bz1 = -1e9f;
    for (const KeptPathSamples& S : samples) {
      for (std::size_t k = 0; k < S.Count(); ++k) {
        const float r = S.w[k] + S.f[k] + 2.0f + blend * 3.0f;
        bx0 = std::min(bx0, S.x[k] - r);
        bz0 = std::min(bz0, S.z[k] - r);
        bx1 = std::max(bx1, S.x[k] + r);
        bz1 = std::max(bz1, S.z[k] + r);
      }
    }
    if (old != nullptr && !old->heightDelta.empty()) {
      bx0 = std::min(bx0, static_cast<float>(old->x0));
      bz0 = std::min(bz0, static_cast<float>(old->z0));
      bx1 = std::max(bx1, static_cast<float>(old->x1));
      bz1 = std::max(bz1, static_cast<float>(old->z1));
    }
    const int x0 = std::clamp(static_cast<int>(std::floor(bx0)), 0, G.width - 1);
    const int z0 = std::clamp(static_cast<int>(std::floor(bz0)), 0, G.height - 1);
    const int x1 = std::clamp(static_cast<int>(std::ceil(bx1)), 0, G.width - 1);
    const int z1 = std::clamp(static_cast<int>(std::ceil(bz1)), 0, G.height - 1);
    if (x1 <= x0 || z1 <= z0) {
      return std::unexpected("the path lies outside the map");
    }
    const int w = x1 - x0 + 1;
    const int h = z1 - z0 + 1;
    // The ground the path starts from: the heights there with its earlier result taken off.
    field::Grid base(w, h, 1.0f, static_cast<float>(x0), static_cast<float>(z0));
    std::vector<std::int32_t> baseWords(static_cast<std::size_t>(w) * h);
    for (int z = 0; z < h; ++z) {
      for (int x = 0; x < w; ++x) {
        std::int32_t word =
          G.words
            [static_cast<std::size_t>(z + z0) * static_cast<std::size_t>(G.width) + static_cast<std::size_t>(x + x0)];
        if (old != nullptr && !old->heightDelta.empty()) {
          const int ox = x + x0 - old->x0;
          const int oz = z + z0 - old->z0;
          const int ow = old->x1 - old->x0 + 1;
          const int oh = old->z1 - old->z0 + 1;
          if (ox >= 0 && oz >= 0 && ox < ow && oz < oh) {
            word -= old->heightDelta
                      [static_cast<std::size_t>(oz) * static_cast<std::size_t>(ow) + static_cast<std::size_t>(ox)];
          }
        }
        word = std::clamp(word, 0, 65535);
        baseWords[static_cast<std::size_t>(z) * w + x] = word;
        base.At(x, z) = static_cast<float>(word) / kWord;
      }
    }
    auto baseShared = Shared(base);
    const auto groundAt = [&](const float x, const float z) {
      return field::SampleWorld(*baseShared, x, z);
    };
    const ModeInfo& m = Info(path.mode);
    field::GridPtr cur = baseShared;
    for (std::size_t i = 0; i < set.size(); ++i) {
      std::vector<float> ys;
      std::vector<float> offs;
      KeptPathHeights(set[i], samples[i], groundAt, G.water, ys, offs);
      if (samples[i].Count() < 1) {
        continue;
      }
      field::OpArgs args;
      ProfileParams(set[i], args.p);
      args.p.arr["pts"] = FlatPts(samples[i], ys, offs);
      args.p.str["mode"] = m.offset ? "offset" : "target";
      args.p.str["clip"] = m.clip;
      args.p.num["strength"] = Clamp(path.strength, 0.0f, 1.0f);
      args.in["a"] = cur;
      field::Grid out;
      if (const auto ran = field::RunOp("path_shape", args, out); !ran) {
        return std::unexpected(ran.error());
      }
      cur = Shared(std::move(out));
    }
    // Blend: the change spreads into the ground around; the blurred change wins where it is stronger.
    if (blend > 0.0f) {
      auto d = std::make_shared<field::Grid>(w, h, 1.0f, static_cast<float>(x0), static_cast<float>(z0));
      for (std::size_t k = 0; k < d->v.size(); ++k) {
        d->v[k] = cur->v[k] - base.v[k];
      }
      field::OpArgs args;
      args.in["a"] = d;
      args.p.num["radius"] = blend;
      field::Grid soft;
      if (const auto ran = field::RunOp("blur", args, soft); !ran) {
        return std::unexpected(ran.error());
      }
      auto next = std::make_shared<field::Grid>(base);
      for (std::size_t k = 0; k < next->v.size(); ++k) {
        const float up = std::max(std::max(d->v[k], 0.0f), std::max(soft.v[k], 0.0f));
        const float down = std::min(std::min(d->v[k], 0.0f), std::min(soft.v[k], 0.0f));
        next->v[k] = base.v[k] + up + down;
      }
      cur = next;
    }
    const auto reachMask = [&](
                             const KeptPath& p,
                             const KeptPathSamples& S,
                             const char* kind,
                             const float soft,
                             const field::GridPtr& like,
                             field::Grid& out
                           ) {
      field::OpArgs args;
      ProfileParams(p, args.p);
      const std::vector<float> zeros(S.Count(), 0.0f);
      args.p.arr["pts"] = FlatPts(S, zeros, zeros);
      args.p.str["kind"] = kind;
      args.p.num["soft"] = soft;
      args.in["like"] = like;
      return field::RunOp("path_mask", args, out);
    };
    if (path.erosion > 0) {
      // Bank erosion: thermal passes over the whole reach (cut walls slump to a natural talus).
      auto reach = std::make_shared<field::Grid>(w, h, 1.0f, static_cast<float>(x0), static_cast<float>(z0));
      for (std::size_t i = 0; i < set.size(); ++i) {
        field::Grid mk;
        if (const auto made = reachMask(set[i], samples[i], "reach", 3.0f, baseShared, mk); !made) {
          return std::unexpected(made.error());
        }
        for (std::size_t k = 0; k < reach->v.size(); ++k) {
          reach->v[k] = std::max(reach->v[k], mk.v[k]);
        }
      }
      field::OpArgs args;
      args.in["a"] = cur;
      args.in["mask"] = reach;
      args.p.num["iterations"] = path.erosion;
      args.p.num["talus"] = 0.5;
      args.p.num["rate"] = 0.5;
      field::Grid eroded;
      if (const auto ran = field::RunOp("thermal", args, eroded); !ran) {
        return std::unexpected(ran.error());
      }
      cur = Shared(std::move(eroded));
    }
    plan.x0 = x0;
    plan.z0 = z0;
    plan.x1 = x1;
    plan.z1 = z1;
    plan.words.resize(static_cast<std::size_t>(w) * h);
    plan.delta.resize(plan.words.size());
    for (std::size_t k = 0; k < plan.words.size(); ++k) {
      const long word = std::clamp(std::lround(cur->v[k] * kWord), 0L, 65535L);
      plan.words[k] = static_cast<std::uint16_t>(word);
      plan.delta[k] = static_cast<std::int32_t>(word) - baseWords[k];
      const float change = static_cast<float>(plan.delta[k]) / kWord;
      plan.lowest = std::min(plan.lowest, change);
      plan.highest = std::max(plan.highest, change);
      const int x = static_cast<int>(k % static_cast<std::size_t>(w)) + x0;
      const int z = static_cast<int>(k / static_cast<std::size_t>(w)) + z0;
      plan.changed +=
        G.words[static_cast<std::size_t>(z) * static_cast<std::size_t>(G.width) + static_cast<std::size_t>(x)] !=
          plan.words[k]
        ? 1u
        : 0u;
    }
    if (wantMasks) {
      // The strata masks over the whole map (cell 1), the path and its images together.
      auto like = std::make_shared<field::Grid>(G.width, G.height, 1.0f, 0.0f, 0.0f);
      for (const KeptPathStrata& e : path.strata) {
        if (e.layer < 1 || e.layer > 8) {
          continue;
        }
        static const char* const kKinds[3] = {"core", "bank", "reach"};
        field::Grid mask(G.width, G.height, 1.0f, 0.0f, 0.0f);
        for (std::size_t i = 0; i < set.size(); ++i) {
          field::Grid mk;
          if (
            const auto made = reachMask(set[i], samples[i], kKinds[static_cast<int>(e.kind)], 1.0f, like, mk); !made
          ) {
            return std::unexpected(made.error());
          }
          for (std::size_t k = 0; k < mask.v.size(); ++k) {
            mask.v[k] = std::max(mask.v[k], mk.v[k]);
          }
        }
        plan.masks.emplace_back(e, std::move(mask));
      }
    }
    return plan;
  }

  std::map<int, std::vector<float>> ApplyKeptPathMasks(
    std::uint64_t* const texels,
    const int width,
    const int height,
    const float mapSize,
    const std::uint8_t remapped,
    const std::vector<std::pair<KeptPathStrata, field::Grid>>& masks,
    const std::map<int, std::vector<float>>* const oldDelta,
    std::size_t& changed
  )
  {
    changed = 0;
    std::map<int, std::vector<float>> deltas;
    if (texels == nullptr || width <= 0 || height <= 0) {
      return deltas;
    }
    const std::size_t count = static_cast<std::size_t>(width) * static_cast<std::size_t>(height);
    // The layers this result touches now or touched before.
    std::map<int, std::vector<float>> weight; // the base weights (earlier result taken off), 0..255
    const auto baseOf = [&](const int layer) -> std::vector<float>& {
      auto it = weight.find(layer);
      if (it != weight.end()) {
        return it->second;
      }
      std::vector<float>& w = weight[layer];
      w.resize(count);
      const bool re = (remapped & (1u << (layer - 1))) != 0;
      const std::vector<float>* od = nullptr;
      if (oldDelta != nullptr) {
        const auto o = oldDelta->find(layer);
        if (o != oldDelta->end() && o->second.size() == count) {
          od = &o->second;
        }
      }
      for (std::size_t i = 0; i < count; ++i) {
        w[i] = MaskWeight(MaskByte(texels[i], layer - 1), re) - (od != nullptr ? (*od)[i] : 0.0f);
        w[i] = std::clamp(w[i], 0.0f, 255.0f);
      }
      return w;
    };
    std::map<int, std::vector<float>> now;
    for (const auto& [e, grid] : masks) {
      std::vector<float>& base = baseOf(e.layer);
      std::vector<float>& cur = now[e.layer];
      if (cur.empty()) {
        cur = base;
      }
      for (int y = 0; y < height; ++y) {
        const float wz = (static_cast<float>(y) + 0.5f) / static_cast<float>(height) * mapSize;
        for (int x = 0; x < width; ++x) {
          const float wx = (static_cast<float>(x) + 0.5f) / static_cast<float>(width) * mapSize;
          const float m = std::clamp(field::SampleWorld(grid, wx, wz), 0.0f, 1.0f) * std::clamp(e.strength, 0.0f, 1.0f);
          if (m <= 0.0f) {
            continue;
          }
          float& c = cur[static_cast<std::size_t>(y) * width + x];
          c += (255.0f - c) * m;
        }
      }
    }
    if (oldDelta != nullptr) {
      for (const auto& [layer, d] : *oldDelta) {
        if (!now.contains(layer) && d.size() == count) {
          now[layer] = baseOf(layer);
        }
      }
    }
    for (auto& [layer, cur] : now) {
      const std::vector<float>& base = baseOf(layer);
      const bool re = (remapped & (1u << (layer - 1))) != 0;
      std::vector<float> d(count, 0.0f);
      bool any = false;
      for (std::size_t i = 0; i < count; ++i) {
        const std::uint8_t before = MaskByte(texels[i], layer - 1);
        const std::uint8_t stored = MaskStoredFor(std::clamp(cur[i], 0.0f, 255.0f), re, before);
        if (stored != before) {
          texels[i] = WithMaskByte(texels[i], layer - 1, stored);
          ++changed;
        }
        d[i] = MaskWeight(stored, re) - base[i];
        any = any || std::abs(d[i]) > 1e-4f;
      }
      if (any) {
        deltas[layer] = std::move(d);
      }
    }
    return deltas;
  }

  std::size_t RemoveKeptPathMasks(
    std::uint64_t* const texels,
    const int width,
    const int height,
    const std::uint8_t remapped,
    const std::map<int, std::vector<float>>& delta
  )
  {
    std::size_t changed = 0;
    const std::size_t count = static_cast<std::size_t>(width) * static_cast<std::size_t>(height);
    for (const auto& [layer, d] : delta) {
      if (layer < 1 || layer > 8 || d.size() != count) {
        continue;
      }
      const bool re = (remapped & (1u << (layer - 1))) != 0;
      for (std::size_t i = 0; i < count; ++i) {
        if (d[i] == 0.0f) {
          continue;
        }
        const std::uint8_t before = MaskByte(texels[i], layer - 1);
        const float w = std::clamp(MaskWeight(before, re) - d[i], 0.0f, 255.0f);
        const std::uint8_t stored = MaskStoredFor(w, re, before);
        if (stored != before) {
          texels[i] = WithMaskByte(texels[i], layer - 1, stored);
          ++changed;
        }
      }
    }
    return changed;
  }

  namespace
  {
    JsonTree ScatterNode(
      const KeptPathScatter& s
    )
    {
      JsonTree n = JsonTree::MakeObject();
      n.Set("on", JsonTree::Flag(s.on));
      n.Set("what", JsonTree::Text(s.what));
      n.Set("spacing", JsonTree::Number(s.spacing));
      n.Set("side", JsonTree::Number(static_cast<int>(s.side)));
      n.Set("lateral", JsonTree::Number(s.lateral));
      n.Set("jitter", JsonTree::Number(s.jitter));
      n.Set("scaleMin", JsonTree::Number(s.scaleMin));
      n.Set("scaleMax", JsonTree::Number(s.scaleMax));
      n.Set("size", JsonTree::Number(s.size));
      n.Set("seed", JsonTree::Number(s.seed));
      return n;
    }

    void ReadScatter(
      const JsonTree* n,
      KeptPathScatter& s
    )
    {
      if (n == nullptr) {
        return;
      }
      s.on = n->Bool("on", s.on);
      s.what = n->Str("what", s.what);
      s.spacing = n->Float("spacing", s.spacing);
      s.side = static_cast<KeptScatterSide>(std::clamp(n->Int("side", static_cast<int>(s.side)), 0, 3));
      s.lateral = n->Float("lateral", s.lateral);
      s.jitter = n->Float("jitter", s.jitter);
      s.scaleMin = n->Float("scaleMin", s.scaleMin);
      s.scaleMax = n->Float("scaleMax", s.scaleMax);
      s.size = n->Float("size", s.size);
      s.seed = n->Int("seed", s.seed);
    }
  } // namespace

  std::string KeptPathsText(
    const KeptPathSet& set
  )
  {
    JsonTree root = JsonTree::MakeObject();
    root.Set("schema", JsonTree::Number(1));
    root.Set("nextId", JsonTree::Number(set.nextId));
    JsonTree& list = root.Set("paths", JsonTree::MakeArray());
    for (const KeptPath& p : set.paths) {
      JsonTree n = JsonTree::MakeObject();
      n.Set("id", JsonTree::Text(p.id));
      n.Set("name", JsonTree::Text(p.name));
      n.Set("kind", JsonTree::Text(p.bezier ? "bezier" : "catmull"));
      n.Set("mode", JsonTree::Text(KeptPathModeId(p.mode)));
      n.Set("closed", JsonTree::Flag(p.closed));
      n.Set("sym", JsonTree::Flag(p.sym));
      n.Set("strength", JsonTree::Number(p.strength));
      n.Set("tension", JsonTree::Number(p.tension));
      n.Set("grade", JsonTree::Number(p.grade));
      n.Set("limitGrade", JsonTree::Flag(p.limitGrade));
      n.Set("interp", JsonTree::Flag(p.interp));
      n.Set("erosion", JsonTree::Number(p.erosion));
      n.Set("blend", JsonTree::Number(p.blend));
      JsonTree& pts = n.Set("points", JsonTree::MakeArray());
      for (const KeptPathPoint& q : p.points) {
        JsonTree pt = JsonTree::MakeObject();
        pt.Set("x", JsonTree::Number(q.x));
        pt.Set("z", JsonTree::Number(q.z));
        pt.Set("w", JsonTree::Number(q.w));
        pt.Set("f", JsonTree::Number(q.f));
        pt.Set("h", JsonTree::Number(q.h));
        pt.Set("abs", JsonTree::Flag(q.abs));
        if (q.autoPin) {
          pt.Set("autoPin", JsonTree::Flag(true));
        }
        pt.Set("bank", JsonTree::Number(q.bank));
        if (q.hasHo) {
          JsonTree& a = pt.Set("ho", JsonTree::MakeArray());
          a.Push(JsonTree::Number(q.ho[0]));
          a.Push(JsonTree::Number(q.ho[1]));
        }
        if (q.hasHi) {
          JsonTree& a = pt.Set("hi", JsonTree::MakeArray());
          a.Push(JsonTree::Number(q.hi[0]));
          a.Push(JsonTree::Number(q.hi[1]));
        }
        pts.Push(std::move(pt));
      }
      JsonTree& prof = n.Set("profile", JsonTree::MakeObject());
      JsonTree& curve = prof.Set("curve", JsonTree::MakeArray());
      for (const auto& c : p.profile.points) {
        curve.Push(JsonTree::Number(c[0]));
        curve.Push(JsonTree::Number(c[1]));
      }
      prof.Set("smooth", JsonTree::Flag(p.profile.smooth));
      prof.Set("symmetric", JsonTree::Flag(p.profile.symmetric));
      prof.Set("preset", JsonTree::Text(p.profile.preset));
      JsonTree& strata = n.Set("strata", JsonTree::MakeArray());
      for (const KeptPathStrata& e : p.strata) {
        JsonTree s = JsonTree::MakeObject();
        s.Set("layer", JsonTree::Number(e.layer));
        s.Set("kind", JsonTree::Number(static_cast<int>(e.kind)));
        s.Set("strength", JsonTree::Number(e.strength));
        strata.Push(std::move(s));
      }
      n.Set("props", ScatterNode(p.props));
      n.Set("decals", ScatterNode(p.decals));
      if (p.skeleton) {
        n.Set("skeleton", JsonTree::Flag(true));
      }
      list.Push(std::move(n));
    }
    return WriteJsonTree(root) + "\n";
  }

  std::expected<KeptPathSet, std::string> ReadKeptPaths(
    const std::string& text
  )
  {
    const auto parsed = ParseJsonTree(text);
    if (!parsed) {
      return std::unexpected(parsed.error());
    }
    const JsonTree& root = *parsed;
    if (root.kind != JsonTree::Kind::Object) {
      return std::unexpected("not a paths file");
    }
    KeptPathSet out;
    out.nextId = std::max(1, root.Int("nextId", 1));
    if (const JsonTree* list = root.Get("paths"); list != nullptr && list->kind == JsonTree::Kind::Array) {
      for (const JsonTree& n : list->items) {
        KeptPath p;
        KeptPathMode mode = KeptPathMode::Carve;
        (void)KeptPathModeFromId(n.Str("mode", "carve"), mode);
        // A fresh id only for a path the file names none for (an argument default would take one every time).
        std::string id = n.Str("id", "");
        if (id.empty() || out.Find(id) != nullptr) {
          id = out.TakeId();
        }
        p = NewKeptPath(mode, n.Str("kind", "catmull") == "bezier", id);
        p.name = n.Str("name", p.name);
        p.closed = n.Bool("closed", false);
        p.sym = n.Bool("sym", false);
        p.strength = n.Float("strength", 1.0f);
        p.tension = n.Float("tension", 1.0f);
        p.grade = n.Float("grade", 0.75f);
        p.limitGrade = n.Bool("limitGrade", false);
        p.interp = n.Bool("interp", true);
        p.erosion = n.Int("erosion", 0);
        p.blend = n.Float("blend", 0.0f);
        if (const JsonTree* pts = n.Get("points"); pts != nullptr) {
          for (const JsonTree& q : pts->items) {
            KeptPathPoint pt;
            pt.x = q.Float("x", 0.0f);
            pt.z = q.Float("z", 0.0f);
            pt.w = q.Float("w", 6.0f);
            pt.f = q.Float("f", 4.0f);
            pt.h = q.Float("h", 0.0f);
            pt.abs = q.Bool("abs", false);
            pt.autoPin = q.Bool("autoPin", false);
            pt.bank = q.Float("bank", 0.0f);
            if (const JsonTree* a = q.Get("ho"); a != nullptr && a->items.size() == 2) {
              pt.hasHo = true;
              pt.ho[0] = static_cast<float>(a->items[0].n);
              pt.ho[1] = static_cast<float>(a->items[1].n);
            }
            if (const JsonTree* a = q.Get("hi"); a != nullptr && a->items.size() == 2) {
              pt.hasHi = true;
              pt.hi[0] = static_cast<float>(a->items[0].n);
              pt.hi[1] = static_cast<float>(a->items[1].n);
            }
            p.points.push_back(pt);
          }
        }
        if (const JsonTree* prof = n.Get("profile"); prof != nullptr) {
          if (const JsonTree* curve = prof->Get("curve"); curve != nullptr && curve->items.size() >= 2) {
            p.profile.points.clear();
            for (std::size_t i = 0; i + 1 < curve->items.size(); i += 2) {
              p.profile.points.push_back(
                {static_cast<float>(curve->items[i].n), static_cast<float>(curve->items[i + 1].n)}
              );
            }
          }
          p.profile.smooth = prof->Bool("smooth", p.profile.smooth);
          p.profile.symmetric = prof->Bool("symmetric", true);
          p.profile.preset = prof->Str("preset", p.profile.preset);
        }
        if (const JsonTree* strata = n.Get("strata"); strata != nullptr) {
          for (std::size_t i = 0; i < strata->items.size() && i < p.strata.size(); ++i) {
            const JsonTree& s = strata->items[i];
            p.strata[i].layer = std::clamp(s.Int("layer", 0), 0, 8);
            p.strata[i].kind = static_cast<KeptStrataKind>(std::clamp(s.Int("kind", 0), 0, 2));
            p.strata[i].strength = s.Float("strength", 1.0f);
          }
        }
        ReadScatter(n.Get("props"), p.props);
        ReadScatter(n.Get("decals"), p.decals);
        p.skeleton = n.Bool("skeleton", false);
        out.paths.push_back(std::move(p));
      }
    }
    return out;
  }
} // namespace faf::editor
