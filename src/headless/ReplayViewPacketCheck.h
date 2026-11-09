#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

#include "remote/ViewPackets.h"

// Engine addition, server mode (plan WP5.2): headless's `--view-packets <army> <file>`. Every
// beat it writes one line with a digest per entity lane (creations, unit creations, entity
// updates, unit updates, deletes, erases) of `army`'s packet:
//
//   - unfocused (`--focus -1`, as the server runs): the packet rebuilt for `army` from the
//     change set (remote/ViewPackets.h);
//   - focused on `army`: the packet the sim itself built, the lockstep client's.
//
// The two files must be equal line for line (the sim plays the same game at any focus, plan
// WPR.2). Each lane is digested in id order; a pointer the client resolves by name (blueprints,
// meshes) is digested by its name, and the animation poses (shared objects, plan WP8) are left
// out. With an entries file (`--view-packets-entries`) it also writes one line per record,
// `beat lane id digest`, so a beat whose lane digests differ can be listed entry by entry:
// missing, extra and changed records (plan WPR.3's equivalence harness). `entriesEvery` keeps the
// records of every Nth beat only, for long games with many armies.

namespace faf::headless
{
  class CReplayViewPacketCheck final : public remote::CViewPackets
  {
  public:
    CReplayViewPacketCheck(
      std::int32_t army, const std::string& path, const std::string& entriesPath, std::uint32_t entriesEvery
    );
    ~CReplayViewPacketCheck() override;

    [[nodiscard]] bool IsOpen() const noexcept { return mFile != nullptr && (mWantEntries == (mEntries != nullptr)); }

    void Install();
    void Uninstall();

    [[nodiscard]] std::string Summary() const;

  protected:
    void OnBeatChanges(moho::Sim& sim, const moho::SSyncData& packet) override;
    void OnViewPackets(moho::Sim& sim) override;

  private:
    void WriteDigest(std::uint32_t beat, const moho::SSyncData& packet, bool rebuilt);

    std::int32_t mArmy;
    std::FILE* mFile = nullptr;
    std::FILE* mEntries = nullptr; // `beat lane id digest` per record, when asked for
    bool mWantEntries = false;
    std::uint32_t mEntriesEvery = 1;
    std::uint64_t mBeats = 0;
    bool mRebuilt = false; // the lines are rebuilt packets (unfocused run)
  };
} // namespace faf::headless
