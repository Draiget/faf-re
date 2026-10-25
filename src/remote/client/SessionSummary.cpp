#include "remote/client/SessionSummary.h"

#include <string>
#include <vector>

#include "gpg/core/utils/Logging.h"
#include "moho/entity/UserEntity.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/UserArmy.h"

// Engine addition, server mode: see SessionSummary.h.

namespace faf::remote::client
{
  namespace
  {
    constexpr int kEveryBeats = 600;

    [[nodiscard]] bool Enabled()
    {
      static const bool enabled = moho::CFG_GetArgOption("/sessionsummary", 0, nullptr);
      return enabled;
    }
  } // namespace

  void NoteSessionBeat(moho::CWldSession& session, const moho::SSyncData& beat)
  {
    if (!Enabled()) {
      return;
    }
    const bool gameOver = beat.mGameOver && session.IsGameOver == 0u;
    if (!gameOver && beat.mCurBeat % kEveryBeats != 0) {
      return;
    }

    std::size_t entities = 0;
    std::size_t units = 0;
    double unitHealth = 0.0;
    std::vector<std::size_t> perArmy(session.userArmies.size(), 0u);
    for (const auto& [id, entity] : session.mEntities) {
      if (entity == nullptr) {
        continue;
      }
      ++entities;
      if (entity->IsUserUnit() == nullptr) {
        continue;
      }
      ++units;
      unitHealth += static_cast<double>(entity->mVariableData.mHealth);
      if (entity->mArmy != nullptr) {
        const auto index = static_cast<std::size_t>(entity->mArmy->mArmyIndex);
        if (index < perArmy.size()) {
          ++perArmy[index];
        }
      }
    }
    std::size_t orphans = 0;
    for (moho::UserEntity* const entity : session.mOrphans) {
      orphans += entity != nullptr ? 1u : 0u;
    }
    std::string armies;
    for (const std::size_t count : perArmy) {
      armies += (armies.empty() ? "" : " ") + std::to_string(count);
    }
    gpg::Logf(
      "session summary beat %d%s: entities %zu, units %zu [%s], orphans %zu, unit health %.1f", beat.mCurBeat,
      gameOver ? " (game over)" : "", entities, units, armies.c_str(), orphans, unitHealth
    );
  }
} // namespace faf::remote::client
