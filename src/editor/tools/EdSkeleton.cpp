#include "editor/tools/EdSkeleton.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <ranges>

namespace faf::editor
{
  namespace
  {
    constexpr float kPi = 3.14159265358979f;

    KeptPathPoint Pt(
      const float x,
      const float z,
      const float w,
      const float f,
      const float h,
      const bool pinned
    )
    {
      KeptPathPoint p;
      p.x = x;
      p.z = z;
      p.w = w;
      p.f = f;
      p.h = h;
      p.abs = pinned;
      p.bank = 0.0f;
      return p;
    }

    KeptPath Make(
      KeptPathSet& ids,
      const KeptPathMode mode,
      const std::string& name,
      std::vector<KeptPathPoint> points,
      const char* preset
    )
    {
      KeptPath path = NewKeptPath(mode, false, ids.TakeId());
      path.name = name;
      path.points = std::move(points);
      path.skeleton = true;
      UseKeptPathPreset(path, preset);
      return path;
    }

    void Dir(
      const SkeletonNode& a,
      const SkeletonNode& b,
      float& ux,
      float& uz,
      float& len
    )
    {
      const float dx = b.x - a.x;
      const float dz = b.z - a.z;
      len = std::hypot(dx, dz);
      if (len < 0.001f) {
        ux = 1.0f;
        uz = 0.0f;
        len = 0.0f;
        return;
      }
      ux = dx / len;
      uz = dz / len;
    }

    struct LanePt
    {
      float x, z, d, t;
    };

    /** Points along a -> b from d0 to len - d1, bowing by `bend` away from the hub (hub lanes bow left), shifted. */
    std::vector<LanePt> LanePoints(
      const SkeletonConnection& conn,
      const SkeletonNode& hub,
      const float d0,
      const float d1,
      const int count,
      const float bend,
      const float shift
    )
    {
      float ux = 0.0f;
      float uz = 0.0f;
      float len = 0.0f;
      Dir(conn.a, conn.b, ux, uz, len);
      const float nx = -uz;
      const float nz = ux;
      const float mx = (conn.a.x + conn.b.x) * 0.5f - hub.x;
      const float mz = (conn.a.z + conn.b.z) * 0.5f - hub.z;
      float sign = nx * mx + nz * mz >= 0.0f ? 1.0f : -1.0f;
      if (conn.b.hub) {
        sign = 1.0f;
      }
      std::vector<LanePt> pts;
      for (int k = 0; k < count; ++k) {
        const float t = count > 1 ? static_cast<float>(k) / static_cast<float>(count - 1) : 0.0f;
        const float d = d0 + (len - d0 - d1) * t;
        const float off = shift + sign * bend * std::sin(kPi * (len > 0.0f ? d / len : 0.0f));
        pts.push_back({conn.a.x + ux * d + nx * off, conn.a.z + uz * d + nz * off, d, t});
      }
      return pts;
    }

    const Pad* PadOf(
      const std::vector<Pad>& pads,
      const std::string& name
    )
    {
      for (const Pad& p : pads) {
        if (p.name == name) {
          return &p;
        }
      }
      return nullptr;
    }
  } // namespace

  const char* SkeletonStyleName(
    const SkeletonStyle style
  ) noexcept
  {
    switch (style) {
    case SkeletonStyle::Open:
      return "Open lanes";
    case SkeletonStyle::Ridge:
      return "Ridge lanes";
    case SkeletonStyle::Ramps:
      return "Ramps and chokes";
    case SkeletonStyle::Islands:
      return "Islands";
    }
    return "?";
  }

  const char* SkeletonStyleId(
    const SkeletonStyle style
  ) noexcept
  {
    switch (style) {
    case SkeletonStyle::Open:
      return "open";
    case SkeletonStyle::Ridge:
      return "ridge";
    case SkeletonStyle::Ramps:
      return "ramps";
    case SkeletonStyle::Islands:
      return "islands";
    }
    return "?";
  }

  const char* SkeletonTopologyName(
    const SkeletonTopology topology
  ) noexcept
  {
    switch (topology) {
    case SkeletonTopology::Ring:
      return "Ring";
    case SkeletonTopology::Hub:
      return "Hub";
    case SkeletonTopology::Both:
      return "Ring and hub";
    }
    return "?";
  }

  std::vector<SkeletonStart> SkeletonStarts(
    const std::vector<PadMarker>& markers
  )
  {
    std::vector<std::pair<int, SkeletonStart>> list;
    for (const PadMarker& m : markers) {
      if (m.name.size() > 5 && m.name.starts_with("ARMY_")) {
        const std::string digits = m.name.substr(5);
        if (!digits.empty() && std::all_of(digits.begin(), digits.end(), [](const char c) {
          return c >= '0' && c <= '9';
        })) {
          list.emplace_back(std::atoi(digits.c_str()), SkeletonStart{m.name, m.x, m.z});
        }
      }
    }
    std::sort(list.begin(), list.end(), [](const auto& a, const auto& b) {
      return a.first < b.first;
    });
    std::vector<SkeletonStart> out;
    for (auto& [n, s] : list) {
      out.push_back(std::move(s));
    }
    return out;
  }

  std::vector<SkeletonConnection> SkeletonConnections(
    const std::vector<SkeletonStart>& starts,
    const SkeletonTopology topology,
    SkeletonNode& hub
  )
  {
    std::vector<SkeletonConnection> list;
    if (starts.empty()) {
      return list;
    }
    float cx = 0.0f;
    float cz = 0.0f;
    for (const SkeletonStart& s : starts) {
      cx += s.x;
      cz += s.z;
    }
    cx /= static_cast<float>(starts.size());
    cz /= static_cast<float>(starts.size());
    hub = SkeletonNode{"hub", cx, cz, true};
    auto sorted = starts | std::views::transform([&](const SkeletonStart& s) {
      return SkeletonNode{s.name, s.x, s.z, false};
    }) |
      std::ranges::to<std::vector<SkeletonNode>>();
    std::stable_sort(sorted.begin(), sorted.end(), [&](const SkeletonNode& a, const SkeletonNode& b) {
      return std::atan2(a.z - cz, a.x - cx) < std::atan2(b.z - cz, b.x - cx);
    });
    const int n = static_cast<int>(sorted.size());
    if ((topology == SkeletonTopology::Ring || topology == SkeletonTopology::Both) && n >= 2) {
      for (int i = 0; i < n; ++i) {
        const int j = (i + 1) % n;
        if (n > 2 || i == 0) {
          list.push_back({sorted[static_cast<std::size_t>(i)], sorted[static_cast<std::size_t>(j)]});
        }
      }
    }
    if ((topology == SkeletonTopology::Hub || topology == SkeletonTopology::Both) && n >= 2) {
      for (int i = 0; i < n; ++i) {
        list.push_back({sorted[static_cast<std::size_t>(i)], hub});
      }
    }
    return list;
  }

  std::vector<Pad> SkeletonPads(
    const std::vector<SkeletonStart>& starts,
    const SkeletonSettings& S,
    const PadSettings& padSettings,
    const std::function<float(float, float)>& ground
  )
  {
    std::vector<Pad> pads;
    if (starts.size() < 2) {
      return pads;
    }
    const bool needPads = S.pads || S.style == SkeletonStyle::Ramps;
    if (!needPads) {
      return pads;
    }
    for (const SkeletonStart& st : starts) {
      Pad p;
      p.name = st.name;
      p.kind = Pad::Kind::Start;
      p.x = st.x;
      p.z = st.z;
      if (S.style == SkeletonStyle::Ramps) {
        p.half = S.plateauHalf;
        p.skirt = std::max(2.0f, S.plateau / 1.6f);
        p.group = -1;
        p.y = ground(st.x, st.z) + S.plateau;
      } else {
        p.half = padSettings.startHalf;
        p.skirt = padSettings.startSkirt;
        p.group = 0;
      }
      pads.push_back(p);
    }
    SkeletonNode hub;
    const std::vector<SkeletonConnection> conns = SkeletonConnections(starts, S.topology, hub);
    const bool usesHub = std::any_of(conns.begin(), conns.end(), [](const SkeletonConnection& c) {
      return c.b.hub;
    });
    if (usesHub) {
      float mean = 0.0f;
      for (const SkeletonStart& st : starts) {
        mean += ground(st.x, st.z);
      }
      mean /= static_cast<float>(starts.size());
      Pad p;
      p.name = "hub";
      p.x = hub.x;
      p.z = hub.z;
      p.half = S.hubHalf;
      p.skirt = S.hubHalf;
      p.group = -1;
      p.y = std::floor(mean * 128.0f + 0.5f) / 128.0f;
      pads.push_back(p);
    }
    return pads;
  }

  std::vector<KeptPath> SkeletonPaths(
    const std::vector<SkeletonStart>& starts,
    const SkeletonSettings& S,
    const PadSettings& padSettings,
    const std::vector<Pad>& pads,
    const std::function<float(float, float)>& ground,
    const float water,
    KeptPathSet& ids
  )
  {
    std::vector<KeptPath> made;
    if (starts.size() < 2) {
      return made;
    }
    SkeletonNode hub;
    const std::vector<SkeletonConnection> conns = SkeletonConnections(starts, S.topology, hub);
    // The distance from a base centre at which a path may start: inside the flat core of its pad.
    const auto inside = [&](const SkeletonNode& node) {
      if (node.hub) {
        return 0.0f;
      }
      const Pad* const p = PadOf(pads, node.name);
      const float half = p != nullptr ? p->half : padSettings.startHalf;
      return std::max(1.0f, half * 0.55f);
    };
    const auto baseY = [&](const SkeletonNode& node) {
      return ground(node.x, node.z);
    };
    // Parallel lanes.
    std::vector<float> offsets;
    {
      const int n = std::max(1, S.lanes);
      const float spacing = 2.0f * (S.laneWidth + S.laneFalloff) + 4.0f;
      for (int k = 1; k <= n; ++k) {
        offsets.push_back((static_cast<float>(k) - static_cast<float>(n + 1) * 0.5f) * spacing);
      }
    }
    const auto lanePath = [&](
                            const SkeletonConnection& conn,
                            const float h0,
                            const float h1,
                            const float shift,
                            const std::string& label,
                            const std::function<float(int)>& widthAt,
                            float d0,
                            float d1
                          ) {
      const std::vector<LanePt> pts = LanePoints(conn, hub, d0, d1, 5, S.bend, shift);
      std::vector<KeptPathPoint> points;
      for (std::size_t k = 0; k < pts.size(); ++k) {
        const bool pinned = k == 0 || k + 1 == pts.size();
        const float h = k == 0 ? h0 : (k + 1 == pts.size() ? h1 : 0.0f);
        points.push_back(
          Pt(pts[k].x, pts[k].z, widthAt ? widthAt(static_cast<int>(k) + 1) : S.laneWidth, S.laneFalloff, h, pinned)
        );
      }
      KeptPath path = Make(ids, KeptPathMode::Ramp, label, std::move(points), "ramp");
      path.limitGrade = true;
      path.grade = S.laneGrade;
      path.strength = 1.0f;
      made.push_back(std::move(path));
    };
    const auto ridges = [&](const SkeletonConnection& conn, const float shift, const std::string& label) {
      const float side = S.laneWidth + S.laneFalloff * 0.5f + S.ridgeGap + S.ridgeWidth;
      float ux = 0.0f;
      float uz = 0.0f;
      float len = 0.0f;
      Dir(conn.a, conn.b, ux, uz, len);
      const float pad = padSettings.startHalf + padSettings.startSkirt;
      const float d0 = std::max(pad + 4.0f, len * 0.18f);
      const float d1 = conn.b.hub ? len * 0.25f : std::max(pad + 4.0f, len * 0.18f);
      for (const float sgn : {-1.0f, 1.0f}) {
        const std::vector<LanePt> pts = LanePoints(conn, hub, d0, d1, 6, S.bend, shift + sgn * side);
        std::vector<KeptPathPoint> points;
        for (std::size_t k = 0; k < pts.size(); ++k) {
          const bool end = k == 0 || k + 1 == pts.size();
          const bool near = k == 1 || k + 2 == pts.size();
          const float taper = end ? 0.2f : (near ? 0.7f : 1.0f);
          points.push_back(Pt(
            pts[k].x, pts[k].z, S.ridgeWidth * (0.6f + 0.4f * taper), S.ridgeWidth * 0.7f, S.ridgeHeight * taper, false
          ));
        }
        made.push_back(
          Make(ids, KeptPathMode::Raise, label + (sgn < 0.0f ? " ridge L" : " ridge R"), std::move(points), "ridge")
        );
      }
    };
    const auto moat = [&](const SkeletonStart& st, const std::string& label) {
      const float g = ground(st.x, st.z);
      const float depth = std::max(S.moatDepth, g - water + S.moatDepth);
      const float r = S.islandRadius + S.moatWidth * 0.5f;
      std::vector<KeptPathPoint> points;
      constexpr int kN = 16;
      for (int k = 0; k < kN; ++k) {
        const float ang = 2.0f * kPi * static_cast<float>(k) / static_cast<float>(kN);
        points.push_back(
          Pt(st.x + std::cos(ang) * r, st.z + std::sin(ang) * r, S.moatWidth * 0.5f, 4.0f, -depth, false)
        );
      }
      KeptPath path = Make(ids, KeptPathMode::Carve, label + " moat", std::move(points), "u");
      path.closed = true;
      made.push_back(std::move(path));
    };
    // A ramp from the plateau of `node` towards `target`: the ramp's bottom and its ground height.
    const auto ramp =
      [&](
        const SkeletonNode& node, const SkeletonNode& target, const std::string& label, float& bx, float& bz, float& by
      ) {
      float ux = 0.0f;
      float uz = 0.0f;
      float len = 0.0f;
      Dir(node, target, ux, uz, len);
      const Pad* const p = PadOf(pads, node.name);
      const float half = p != nullptr ? p->half : S.plateauHalf;
      const float skirt = p != nullptr ? p->skirt : std::max(2.0f, S.plateau / 1.6f);
      const float top = p != nullptr && p->group == -1 ? p->y : ground(node.x, node.z) + S.plateau;
      const float edge = half / std::max({std::abs(ux), std::abs(uz), 0.01f});
      const float rampLen = std::max(8.0f, S.plateau / std::max(0.2f, S.laneGrade) * 1.25f);
      const float topAt = half * 0.55f;
      const float bottom = edge + skirt + rampLen;
      bx = node.x + ux * bottom;
      bz = node.z + uz * bottom;
      by = ground(bx, bz);
      std::vector<KeptPathPoint> points = {
        Pt(node.x + ux * topAt, node.z + uz * topAt, S.rampWidth, 3.0f, top, true),
        Pt(
          node.x + ux * (topAt + bottom) * 0.5f, node.z + uz * (topAt + bottom) * 0.5f, S.rampWidth, 3.0f, 0.0f, false
        ),
        Pt(bx, bz, S.rampWidth, 3.0f, by, true),
      };
      KeptPath path = Make(ids, KeptPathMode::Ramp, label, std::move(points), "ramp");
      path.limitGrade = true;
      path.grade = S.laneGrade;
      made.push_back(std::move(path));
    };
    const std::string style = SkeletonStyleId(S.style);
    if (S.style == SkeletonStyle::Islands) {
      for (const SkeletonStart& st : starts) {
        moat(st, "Skeleton " + st.name);
      }
    }
    int k = 0;
    for (const SkeletonConnection& conn : conns) {
      ++k;
      int j = 0;
      for (const float shift : offsets) {
        ++j;
        char label[96];
        (void)std::snprintf(label, sizeof(label), "Skeleton %s %d.%d", style.c_str(), k, j);
        const std::string name = label;
        if (S.style == SkeletonStyle::Ramps) {
          float ax = 0.0f, az = 0.0f, ay = 0.0f, bx = 0.0f, bz = 0.0f, by = 0.0f;
          ramp(conn.a, conn.b, name + " ramp A", ax, az, ay);
          if (conn.b.hub) {
            bx = conn.b.x;
            bz = conn.b.z;
            by = baseY(conn.b);
          } else {
            ramp(conn.b, conn.a, name + " ramp B", bx, bz, by);
          }
          SkeletonConnection sub{{"ra", ax, az, false}, {"rb", bx, bz, conn.b.hub}};
          lanePath(sub, ay, by, shift, name + " choke lane", [&S](const int q) {
            if (q == 3) {
              return S.chokeWidth;
            }
            if (q == 2 || q == 4) {
              return (S.chokeWidth + S.laneWidth) * 0.5f;
            }
            return S.laneWidth;
          }, 0.0f, conn.b.hub ? inside(conn.b) : 0.0f);
        } else if (S.style == SkeletonStyle::Islands) {
          const float d0 = std::max(inside(conn.a), 4.0f);
          const float d1 = conn.b.hub ? 2.0f : std::max(inside(conn.b), 4.0f);
          lanePath(conn, baseY(conn.a), baseY(conn.b), shift, name + " causeway", [&S](int) {
            return S.bridgeWidth;
          }, d0, d1);
        } else {
          lanePath(conn, baseY(conn.a), baseY(conn.b), shift, name, nullptr, inside(conn.a), inside(conn.b));
          if (S.style == SkeletonStyle::Ridge) {
            ridges(conn, shift, name);
          }
        }
      }
    }
    return made;
  }
} // namespace faf::editor
