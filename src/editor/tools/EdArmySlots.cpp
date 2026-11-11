#include "editor/tools/EdArmySlots.h"

#include <cmath>
#include <cstdlib>

namespace faf::editor
{
  std::vector<int> MirrorPartners(
    const std::vector<std::optional<std::array<float, 2>>>& starts,
    const int width,
    const int height,
    const Symmetry symmetry,
    const int turns
  )
  {
    std::vector<int> partners(starts.size(), -1);
    for (std::size_t i = 0; i < starts.size(); ++i) {
      if (!starts[i]) {
        continue;
      }
      float copyX[kMaxSymmetryCopies];
      float copyZ[kMaxSymmetryCopies];
      const int copies =
        HeightBrushCentres(width, height, (*starts[i])[0], (*starts[i])[1], symmetry, turns, copyX, copyZ);
      if (copies < 2) {
        continue;
      }
      float nearest = 1e30f;
      for (std::size_t k = 0; k < starts.size(); ++k) {
        if (!starts[k]) {
          continue;
        }
        const float d = std::hypot((*starts[k])[0] - copyX[1], (*starts[k])[1] - copyZ[1]);
        if (d < nearest) {
          nearest = d;
          partners[i] = static_cast<int>(k);
        }
      }
      if (partners[i] == static_cast<int>(i)) {
        partners[i] = -1;
      }
    }
    return partners;
  }

  std::vector<int> PairMirroredSlots(
    const std::vector<int>& partners
  )
  {
    std::vector<int> order;
    std::vector<bool> placed(partners.size(), false);
    // The pairs first, each where its first slot was.
    for (std::size_t i = 0; i < partners.size(); ++i) {
      const int partner = partners[i];
      if (placed[i] || partner < 0 || placed[static_cast<std::size_t>(partner)]) {
        continue;
      }
      order.push_back(static_cast<int>(i));
      order.push_back(partner);
      placed[i] = true;
      placed[static_cast<std::size_t>(partner)] = true;
    }
    for (std::size_t i = 0; i < partners.size(); ++i) {
      if (!placed[i]) {
        order.push_back(static_cast<int>(i));
      }
    }
    return order;
  }

  std::string NextArmyName(
    const std::vector<std::string>& names
  )
  {
    int highest = 0;
    for (const std::string& name : names) {
      if (name.rfind("ARMY_", 0) == 0 && name.size() > 5) {
        char* end = nullptr;
        const long number = std::strtol(name.c_str() + 5, &end, 10);
        if (end != nullptr && *end == '\0' && number > highest) {
          highest = static_cast<int>(number);
        }
      }
    }
    return "ARMY_" + std::to_string(highest + 1);
  }
} // namespace faf::editor
