#include "editor/tools/EdArrange.h"

#include <algorithm>
#include <cmath>
#include <numeric>

namespace faf::editor
{
  namespace
  {
    constexpr float kPi = 3.14159265358979f;

    struct OpInfo
    {
      const char* id;
      const char* title;
    };

    constexpr OpInfo kOps[] = {
      {"alignleft", "Align left"},
      {"aligncentrex", "Align centre X"},
      {"alignright", "Align right"},
      {"aligntop", "Align top"},
      {"aligncentrez", "Align centre Z"},
      {"alignbottom", "Align bottom"},
      {"distributex", "Distribute X"},
      {"distributez", "Distribute Z"},
      {"circle", "Arrange in a circle"},
      {"snap", "Snap to grid"},
      {"mirrorx", "Mirror left-right"},
      {"mirrorz", "Mirror top-bottom"},
    };
    static_assert(sizeof(kOps) / sizeof(kOps[0]) == static_cast<std::size_t>(ArrangeOp::Count));

    /** Evenly between the first and the last in the order of `along`; a tie keeps the given order. */
    void Distribute(
      std::vector<float>& along
    )
    {
      std::vector<std::size_t> order(along.size());
      std::iota(order.begin(), order.end(), std::size_t{0});
      std::stable_sort(order.begin(), order.end(), [&](const std::size_t a, const std::size_t b) {
        return along[a] < along[b];
      });
      const float first = along[order.front()];
      const float last = along[order.back()];
      const float gap = (last - first) / static_cast<float>(order.size() - 1);
      for (std::size_t k = 0; k < order.size(); ++k) {
        along[order[k]] = first + gap * static_cast<float>(k);
      }
    }

    float WrapAngle(
      float a
    )
    {
      while (a > kPi) {
        a -= 2.0f * kPi;
      }
      while (a <= -kPi) {
        a += 2.0f * kPi;
      }
      return a;
    }
  } // namespace

  int ArrangeMinimum(
    const ArrangeOp op
  ) noexcept
  {
    switch (op) {
    case ArrangeOp::DistributeX:
    case ArrangeOp::DistributeZ:
    case ArrangeOp::Circle:
      return 3;
    case ArrangeOp::Snap:
      return 1;
    default:
      return 2;
    }
  }

  const char* ArrangeTitle(
    const ArrangeOp op
  ) noexcept
  {
    return op < ArrangeOp::Count ? kOps[static_cast<int>(op)].title : "";
  }

  const char* ArrangeId(
    const ArrangeOp op
  ) noexcept
  {
    return op < ArrangeOp::Count ? kOps[static_cast<int>(op)].id : "";
  }

  ArrangeOp ArrangeFromId(
    const std::string& id
  ) noexcept
  {
    for (int i = 0; i < static_cast<int>(ArrangeOp::Count); ++i) {
      if (id == kOps[i].id) {
        return static_cast<ArrangeOp>(i);
      }
    }
    return ArrangeOp::Count;
  }

  bool Arrange(
    const ArrangeOp op,
    ArrangePlaces& places,
    const float step
  )
  {
    const std::size_t n = places.x.size();
    if (places.z.size() != n || op >= ArrangeOp::Count || static_cast<int>(n) < ArrangeMinimum(op)) {
      return false;
    }
    places.heading.resize(n, 0.0f);
    const auto [minX, maxX] = std::minmax_element(places.x.begin(), places.x.end());
    const auto [minZ, maxZ] = std::minmax_element(places.z.begin(), places.z.end());
    const float left = *minX, right = *maxX, top = *minZ, bottom = *maxZ;
    // The middle of the box around them (the mirrors' line, as an editor's "mirror selection" turns it in place).
    const float midX = (left + right) * 0.5f;
    const float midZ = (top + bottom) * 0.5f;
    switch (op) {
    case ArrangeOp::AlignLeft:
      std::fill(places.x.begin(), places.x.end(), left);
      break;
    case ArrangeOp::AlignCentreX:
      std::fill(places.x.begin(), places.x.end(), midX);
      break;
    case ArrangeOp::AlignRight:
      std::fill(places.x.begin(), places.x.end(), right);
      break;
    case ArrangeOp::AlignTop:
      std::fill(places.z.begin(), places.z.end(), top);
      break;
    case ArrangeOp::AlignCentreZ:
      std::fill(places.z.begin(), places.z.end(), midZ);
      break;
    case ArrangeOp::AlignBottom:
      std::fill(places.z.begin(), places.z.end(), bottom);
      break;
    case ArrangeOp::DistributeX:
      Distribute(places.x);
      break;
    case ArrangeOp::DistributeZ:
      Distribute(places.z);
      break;
    case ArrangeOp::Circle: {
      // About their mean place; each keeps its turn round it, the first keeps its angle.
      const float cx = std::accumulate(places.x.begin(), places.x.end(), 0.0f) / static_cast<float>(n);
      const float cz = std::accumulate(places.z.begin(), places.z.end(), 0.0f) / static_cast<float>(n);
      float radius = 0.0f;
      std::vector<float> angle(n);
      for (std::size_t i = 0; i < n; ++i) {
        radius += std::hypot(places.x[i] - cx, places.z[i] - cz);
        angle[i] = std::atan2(places.z[i] - cz, places.x[i] - cx);
      }
      radius /= static_cast<float>(n);
      if (radius < 1.0f) {
        radius = 4.0f; // all in one place: a small ring
      }
      std::vector<std::size_t> order(n);
      std::iota(order.begin(), order.end(), std::size_t{0});
      std::stable_sort(order.begin(), order.end(), [&](const std::size_t a, const std::size_t b) {
        return angle[a] < angle[b];
      });
      const float start = angle[order.front()];
      for (std::size_t k = 0; k < n; ++k) {
        const float a = start + 2.0f * kPi * static_cast<float>(k) / static_cast<float>(n);
        places.x[order[k]] = cx + radius * std::cos(a);
        places.z[order[k]] = cz + radius * std::sin(a);
      }
      break;
    }
    case ArrangeOp::Snap:
      if (!(step > 0.0f)) {
        return false;
      }
      for (std::size_t i = 0; i < n; ++i) {
        places.x[i] = std::round(places.x[i] / step) * step;
        places.z[i] = std::round(places.z[i] / step) * step;
      }
      break;
    case ArrangeOp::MirrorX:
      for (std::size_t i = 0; i < n; ++i) {
        places.x[i] = 2.0f * midX - places.x[i];
        places.heading[i] = WrapAngle(-places.heading[i]); // (sin h, cos h) -> (-sin h, cos h)
      }
      break;
    case ArrangeOp::MirrorZ:
      for (std::size_t i = 0; i < n; ++i) {
        places.z[i] = 2.0f * midZ - places.z[i];
        places.heading[i] = WrapAngle(kPi - places.heading[i]); // (sin h, cos h) -> (sin h, -cos h)
      }
      break;
    default:
      return false;
    }
    return true;
  }
} // namespace faf::editor
