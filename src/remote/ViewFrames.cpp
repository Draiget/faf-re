#include "remote/ViewFrames.h"

#include <utility>

#include "moho/entity/Entity.h"
#include "moho/entity/EntityDb.h"
#include "moho/sim/Sim.h"
#include "remote/VisibilityOracle.h"

// Engine addition, server mode: see ViewFrames.h.

namespace faf::remote
{
  CViewFrames::CViewFrames(const wire::SContentTables& tables, const wire::SFrameCodec& codec)
    : mTables(tables)
    , mCodec(codec)
  {}

  CViewFrames::~CViewFrames() = default;

  void CViewFrames::OnViewPackets(moho::Sim& sim)
  {
    const auto armyCount = static_cast<std::size_t>(ArmyCount());
    while (mBuilders.size() < armyCount) {
      mBuilders.push_back(std::make_unique<CViewFrameBuilder>(mTables, mCodec));
      mFrames.emplace_back();
      mWithheld.push_back(0u);
    }

    for (std::size_t army = 0; army < armyCount; ++army) {
      CViewFrameBuilder& builder = *mBuilders[army];
      builder.Apply(Packet(static_cast<std::int32_t>(army)));
      wire::SViewFrame frame = builder.Build(sim.mCurBeat);

      // Plan §6: a plain entity in mode ReconGrid goes out only while the view sees it.
      std::uint32_t withheld = 0;
      std::vector<wire::SEntityRecord> kept;
      kept.reserve(frame.entities.size());
      for (wire::SEntityRecord& record : frame.entities) {
        moho::Entity* entity = nullptr;
        if (sim.mEntityDB != nullptr) {
          const auto found = sim.mEntityDB->mAllUnits.find(record.id);
          if (found != sim.mEntityDB->mAllUnits.end()) {
            entity = found->second;
          }
        }
        if (entity != nullptr && !CanViewSee(sim, static_cast<std::int32_t>(army), *entity)) {
          ++withheld;
          continue;
        }
        kept.push_back(std::move(record));
      }
      frame.entities = std::move(kept);
      mFrames[army] = std::move(frame);
      mWithheld[army] = withheld;
    }
    OnViewFrames(sim);
  }
} // namespace faf::remote
