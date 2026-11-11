#pragma once

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "legacy/containers/AutoPtr.h"

// Engine addition (neural bot, milestone M1): headless's `--bot-obs`. A replay played with
// `--focus <army>` writes what that army's player had to decide on, and what they decided:
//
//   - the view: built only from the sync packets the sim publishes for the focus army, which
//     are what a lockstep client focused on that army receives (remote/VisibilityOracle.h).
//     Another army's unit, an ally's too, arrives only as a recon blip, and is written at the
//     three levels the UI shows it: the generic icon's class (structure, land, naval, air)
//     while detected; the unit's own strategic icon and its owner once seen (intel bit 0x10,
//     `PickUnitStrategicIconTexture`); its exact blueprint while its mesh is drawn
//     (`UserUnit::UpdateVisibility` 0x008C09B0: mobile while in sight, RECON_LOSNow; a
//     structure once seen, RECON_LOSEver). Its health only while in sight now. Known fakes
//     (0x20), whose icon the UI suppresses, are left out. Other armies' economies, which every
//     client receives, are left out too.
//   - the decisions: every command that army's command sources sent, decoded from the replay
//     stream with a decoder of its own (the sim's decoder hands it each message first). Orders
//     keep only the army's own units. A command is tagged with the beat it runs in, whose
//     packet first shows it: the driver publishes beat 0 before any Advance message, and each
//     Advance runs one more beat (`Sim::AdvanceBeat` 0x00749F40 ignores the count). A sample
//     holds the commands of the beats up to its own, all decoded before its packet existed, so
//     the file is the same whatever the sim's lead.
//
// One JSON object per line: a header, then one sample every `every` beats with the commands
// sent since the last one. tools/neural-bot reads it. A sample's view already shows its own
// commands running, so the view a command was decided on is an earlier line's. Not written
// yet: props and wrecks (reclaim), the queues of the army's own units, the Lua `Sync` table,
// and sim callbacks' arguments. Nothing here writes to the sim; the
// sim's checksums and published state are the same with and without it.

namespace moho
{
  class CDecoder;
  class RRuleGameRules;
  struct CMessage;
  struct SSyncData;
} // namespace moho

namespace LuaPlus
{
  class LuaState;
}

namespace gpg
{
  class Stream;
}

namespace faf::headless
{
  class CBotCommandRecorder;

  class CBotObservation
  {
  public:
    CBotObservation(moho::RRuleGameRules& rules, int army, std::vector<std::uint32_t> sources, int every);
    ~CBotObservation();

    CBotObservation(const CBotObservation&) = delete;
    CBotObservation& operator=(const CBotObservation&) = delete;

    /** Opens `path` and writes the header line. False when it can't be written. */
    [[nodiscard]] bool Open(const std::string& path, const std::string& replayPath);
    /** Watches every message the sim's decoder receives from now on (the decoder's one observer). */
    void Install();
    void Uninstall();

    /** One published beat, on the thread that takes packets off the driver. */
    void OnPacket(const moho::SSyncData& packet);
    /** Writes the commands not yet written and closes the file. The observer stays installed until destruction. */
    void Finish();

    [[nodiscard]] std::string Summary() const;

  private:
    struct SEntity
    {
      std::string blueprint;
      std::string icon; // the blueprint's strategic icon name
      bool blip = false;
      bool mobile = true;          // as the client's UserUnit::IsMobile
      bool blueprintMobile = true; // as REntityBlueprint::IsMobile, which picks the generic icon
      std::int32_t layer = 0;
      bool dead = false;
      std::int32_t visibilityMode = 0;
      std::uint32_t recon = 0;
      float x = 0.0f;
      float y = 0.0f;
      float z = 0.0f;
      float health = 0.0f;
      float maxHealth = 0.0f;
      float fraction = 1.0f;
      float workProgress = 0.0f;
      bool beingBuilt = false;
      bool busy = false;
    };

    static void Observe(const moho::CMessage& message, void* context);
    void OnMessage(const moho::CMessage& message);
    void WriteSample(const moho::SSyncData& packet);
    void WriteCommands(int upToBeat, std::string& line);
    [[nodiscard]] bool TypeKnown(const SEntity& entity) const noexcept;
    [[nodiscard]] bool ContactShown(const SEntity& entity) const noexcept;
    [[nodiscard]] bool InSightNow(const SEntity& entity) const noexcept;
    [[nodiscard]] bool IconKnown(const SEntity& entity) const noexcept;
    [[nodiscard]] static const char* GenericClass(const SEntity& entity) noexcept;

    int mArmy;
    std::vector<std::uint32_t> mSources;
    int mEvery;
    std::FILE* mFile = nullptr;

    std::unordered_map<std::uint32_t, SEntity> mEntities;
    std::string mEconomy;      // the focus army's last economy, as JSON
    std::string mPlayableRect; // set when the packet changes it, written once

    std::unique_ptr<CBotCommandRecorder> mRecorder;
    std::unique_ptr<LuaPlus::LuaState> mLuaState; // the decoder's own, apart from the sim's
    fa::auto_ptr<gpg::Stream> mNoRecording;
    std::unique_ptr<moho::CDecoder> mDecoder;
    bool mInside = false;
    bool mInstalled = false;

    std::uint64_t mSamples = 0;
    std::uint64_t mOwnRows = 0;
    std::uint64_t mContactRows = 0;
    std::uint64_t mKnownContactRows = 0;
    std::uint64_t mIconContactRows = 0;
    std::uint64_t mCommandsWritten = 0;
    std::atomic<std::uint64_t> mDecodeErrors{0}; // messages this observation's decoder threw on (sim's thread)
  };
} // namespace faf::headless
