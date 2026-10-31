#include "remote/ViewFrames.h"

#include <utility>

#include "moho/command/CCommandDb.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityDb.h"
#include "moho/sim/SSTIArmyVariableData.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimDriver.h"
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
      mIdMaps.push_back(std::make_unique<CViewIdMap>(static_cast<std::int32_t>(mBuilders.size())));
      mRetiring.emplace_back();
      mRetired.emplace_back();
      mBuilders.push_back(std::make_unique<CViewFrameBuilder>(mTables, mCodec));
      mFrames.emplace_back();
      mWithheld.push_back(0u);
    }

    for (std::size_t army = 0; army < armyCount; ++army) {
      CViewFrameBuilder& builder = *mBuilders[army];
      const moho::SSyncData& packet = Packet(static_cast<std::int32_t>(army));
      builder.Apply(packet);
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

      if (mIdMapsOn) {
        // Plan WP5.9: the view's own ids. A command is the view's own when its top byte is one of
        // the command sources allowed to command the view's army (`UserCommandIssue.cpp:372`
        // packs the client's source there).
        CViewIdMap& map = *mIdMaps[army];
        // What the last beat retired goes first: its frame could still name those ids (a unit's
        // target blip deleted on the same beat), and named them with the ids the view had. A
        // command retires once the sim's command database no longer has it: the sim deletes a
        // finished command while it publishes the beat's commands (`CCommandDB::PublishSyncData`),
        // after the walk this observer sees, so a command released on one beat goes on the next.
        map.RetireEntities(mRetired[army]);
        if (const moho::CCommandDB* const commands = sim.mCommandDB; commands != nullptr) {
          map.RetireCommandsUnless([commands](const std::uint32_t simId) {
            return commands->commands.find(simId) != commands->commands.end();
          });
        }
        const moho::BVIntSet* sources = nullptr;
        if (army < packet.mArmyUpdates.size()) {
          sources = &packet.mArmyUpdates[army].mValidCommandSources;
        }
        map.Translate(frame, [sources](const std::uint32_t commandId) {
          return sources != nullptr && sources->Contains(commandId >> 24u);
        });
        // A deleted or erased entity's id retires once the client holds no record of it (an
        // orphan keeps its view id while it is shown).
        std::unordered_set<std::uint32_t>& retiring = mRetiring[army];
        retiring.insert(packet.mDeleteIds.begin(), packet.mDeleteIds.end());
        retiring.insert(packet.mEraseIds.begin(), packet.mEraseIds.end());
        std::vector<std::uint32_t>& next = mRetired[army];
        next.clear();
        for (auto it = retiring.begin(); it != retiring.end();) {
          if (builder.Holds(*it)) {
            ++it;
            continue;
          }
          next.push_back(*it);
          it = retiring.erase(it);
        }
      }

      mFrames[army] = std::move(frame);
      mWithheld[army] = withheld;
    }
    OnViewFrames(sim);
  }
} // namespace faf::remote
