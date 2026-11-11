#include "headless/BotObservation.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <unordered_set>
#include <utility>

#include "lua/LuaObject.h"
#include "moho/ai/IAiReconDB.h"
#include "moho/command/ICommandSink.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/misc/CDecoder.h"
#include "moho/net/CMessage.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/SSTIArmyVariableData.h"
#include "moho/sim/SimDriver.h"
#include "moho/unit/core/Unit.h"

// Engine addition: see BotObservation.h.

namespace faf::headless
{
  namespace
  {
    constexpr std::uint32_t kBlipKind = 3u;         // top 4 bits of a recon blip's id (remote/client/ViewMerge.h)
    constexpr std::uint32_t kShownMapWide = 0x100u; // added to a contact's recon flags: visibility mode MapPlayableRect

    [[nodiscard]] constexpr std::uint32_t IdKind(
      const std::uint32_t id
    ) noexcept
    {
      return id >> 28u;
    }
    [[nodiscard]] constexpr std::uint32_t IdArmy(
      const std::uint32_t id
    ) noexcept
    {
      return (id >> 20u) & 0xFFu;
    }

    constexpr const char* kCommandTypeNames[] = {
      "None",
      "Stop",
      "Move",
      "Dive",
      "FormMove",
      "BuildSiloTactical",
      "BuildSiloNuke",
      "BuildFactory",
      "BuildMobile",
      "BuildAssist",
      "Attack",
      "FormAttack",
      "Nuke",
      "Tactical",
      "Teleport",
      "Guard",
      "Patrol",
      "Ferry",
      "FormPatrol",
      "Reclaim",
      "Repair",
      "Capture",
      "TransportLoadUnits",
      "TransportReverseLoadUnits",
      "TransportUnloadUnits",
      "TransportUnloadSpecificUnits",
      "DetachFromTransport",
      "Upgrade",
      "Script",
      "AssistCommander",
      "KillSelf",
      "DestroySelf",
      "Sacrifice",
      "Pause",
      "OverCharge",
      "AggressiveMove",
      "FormAggressiveMove",
      "AssistMove",
      "SpecialAction",
      "Dock",
    };

    [[nodiscard]] const char* CommandTypeName(
      const moho::EUnitCommandType type
    ) noexcept
    {
      const auto index = static_cast<std::size_t>(type);
      return index < std::size(kCommandTypeNames) ? kCommandTypeNames[index] : "Unknown";
    }

    void AppendEscaped(
      std::string& out,
      const char* const text
    )
    {
      out += '"';
      for (const char* at = text != nullptr ? text : ""; *at != '\0'; ++at) {
        const auto c = static_cast<unsigned char>(*at);
        if (c == '"' || c == '\\') {
          out += '\\';
          out += static_cast<char>(c);
        } else if (c < 0x20u) {
          char escaped[8];
          std::snprintf(escaped, sizeof(escaped), "\\u%04x", static_cast<unsigned>(c));
          out += escaped;
        } else {
          out += static_cast<char>(c);
        }
      }
      out += '"';
    }

    void AppendFloat(
      std::string& out,
      const float value
    )
    {
      char text[32];
      std::snprintf(text, sizeof(text), "%.1f", static_cast<double>(value));
      out += text;
    }

    void AppendPair(
      std::string& out,
      const float mass,
      const float energy
    )
    {
      out += '[';
      AppendFloat(out, mass);
      out += ',';
      AppendFloat(out, energy);
      out += ']';
    }

    using EntitySet = moho::BVSet<moho::EntId, moho::EntIdUniverse>;

    void AppendIds(
      std::string& out,
      const EntitySet& entities
    )
    {
      out += '[';
      bool first = true;
      entities.ForEachValue([&](const unsigned int id) {
        if (!first) {
          out += ',';
        }
        first = false;
        out += std::to_string(id);
      });
      out += ']';
    }

    void AppendTarget(
      std::string& out,
      const moho::SSTITarget& target
    )
    {
      switch (target.mType) {
      case moho::EAiTargetType::AITARGET_Entity:
        out += "{\"entity\":" + std::to_string(target.mEntityId) + '}';
        return;
      case moho::EAiTargetType::AITARGET_Ground:
        out += "{\"ground\":[";
        AppendFloat(out, target.mPos.x);
        out += ',';
        AppendFloat(out, target.mPos.y);
        out += ',';
        AppendFloat(out, target.mPos.z);
        out += "]}";
        return;
      default:
        out += "null";
        return;
      }
    }
  } // namespace

  /**
   * The decisions half: a command sink fed by a decoder of its own. It keeps the commands of the
   * focus army's sources, as JSON, tagged with the beat they were sent in. Called on the sim's
   * thread; read on the packet thread.
   */
  class CBotCommandRecorder final : public moho::ICommandSink
  {
  public:
    CBotCommandRecorder(
      const int army,
      std::vector<std::uint32_t> sources
    )
      : mArmy(static_cast<std::uint32_t>(army))
      , mSources(std::move(sources))
    {}

    /** Hands over the commands of beats up to `beat`, oldest first. */
    void Take(
      const int beat,
      std::vector<std::pair<int, std::string>>& out
    )
    {
      const std::lock_guard<std::mutex> lock(mMutex);
      auto split = std::stable_partition(mCommands.begin(), mCommands.end(), [beat](const auto& entry) {
        return entry.first <= beat;
      });
      out.insert(out.end(), std::make_move_iterator(mCommands.begin()), std::make_move_iterator(split));
      mCommands.erase(mCommands.begin(), split);
    }

    [[nodiscard]] std::uint64_t Recorded() const
    {
      const std::lock_guard<std::mutex> lock(mMutex);
      return mRecorded;
    }

    void SetCommandSource(
      const moho::CommandSourceId sourceId
    ) override
    {
      const auto source = static_cast<std::uint32_t>(sourceId);
      mOurs = std::find(mSources.begin(), mSources.end(), source) != mSources.end();
    }

    void AdvanceBeat(
      int
    ) override
    {
      ++mBeat;
    }

    void IssueCommand(
      const EntitySet& entities,
      const moho::SSTICommandIssueData& data,
      const bool clear
    ) override
    {
      Issue("issue", entities, data, clear);
    }

    void IssueFactoryCommand(
      const EntitySet& entities,
      const moho::SSTICommandIssueData& data,
      const bool clear
    ) override
    {
      Issue("factory", entities, data, clear);
    }

    void IncreaseCommandCount(
      const moho::CmdId id,
      const int count
    ) override
    {
      if (Foreign(id)) {
        return;
      }
      Record(
        "{\"op\":\"count\",\"cmd\":" + std::to_string(static_cast<std::int32_t>(id)) +
        ",\"delta\":" + std::to_string(count) + '}'
      );
    }

    void DecreaseCommandCount(
      const moho::CmdId id,
      const int count
    ) override
    {
      if (Foreign(id)) {
        return;
      }
      Record(
        "{\"op\":\"count\",\"cmd\":" + std::to_string(static_cast<std::int32_t>(id)) + ",\"delta\":-" +
        std::to_string(count) + '}'
      );
    }

    void SetCommandTarget(
      const moho::CmdId id,
      const moho::SSTITarget& target
    ) override
    {
      if (Foreign(id)) {
        return;
      }
      std::string json =
        "{\"op\":\"retarget\",\"cmd\":" + std::to_string(static_cast<std::int32_t>(id)) + ",\"target\":";
      AppendTarget(json, target);
      json += '}';
      Record(std::move(json));
    }

    void SetCommandType(
      const moho::CmdId id,
      const moho::EUnitCommandType type
    ) override
    {
      if (Foreign(id)) {
        return;
      }
      std::string json = "{\"op\":\"retype\",\"cmd\":" + std::to_string(static_cast<std::int32_t>(id)) + ",\"type\":";
      AppendEscaped(json, CommandTypeName(type));
      json += '}';
      Record(std::move(json));
    }

    void SetCommandCells(
      const moho::CmdId id,
      const gpg::core::FastVector<moho::SOCellPos>&,
      const Wm3::Vector3<float>& target
    ) override
    {
      if (Foreign(id)) {
        return;
      }
      std::string json = "{\"op\":\"cells\",\"cmd\":" + std::to_string(static_cast<std::int32_t>(id)) + ",\"pos\":[";
      AppendFloat(json, target.x);
      json += ',';
      AppendFloat(json, target.y);
      json += ',';
      AppendFloat(json, target.z);
      json += "]}";
      Record(std::move(json));
    }

    void RemoveCommandFromUnitQueue(
      const moho::CmdId id,
      const moho::EntId unitId
    ) override
    {
      if (!Own(static_cast<std::uint32_t>(unitId))) {
        return;
      }
      Record(
        "{\"op\":\"dequeue\",\"cmd\":" + std::to_string(static_cast<std::int32_t>(id)) +
        ",\"unit\":" + std::to_string(static_cast<std::uint32_t>(unitId)) + '}'
      );
    }

    void LuaSimCallback(
      const char* const fnName,
      const LuaPlus::LuaObject&,
      const EntitySet& entities
    ) override
    {
      // The arguments are left out for now: their keys vary by callback (BotObservation.h).
      std::string json = "{\"op\":\"callback\",\"name\":";
      AppendEscaped(json, fnName);
      json += ",\"units\":";
      AppendIds(json, OwnUnits(entities));
      json += '}';
      Record(std::move(json));
    }

    void ProcessInfoPair(
      const moho::EntId entityId,
      const gpg::StrArg key,
      const gpg::StrArg value
    ) override
    {
      if (!Own(static_cast<std::uint32_t>(entityId))) {
        return;
      }
      std::string json =
        "{\"op\":\"info\",\"unit\":" + std::to_string(static_cast<std::uint32_t>(entityId)) + ",\"key\":";
      AppendEscaped(json, key);
      json += ",\"value\":";
      AppendEscaped(json, value);
      json += '}';
      Record(std::move(json));
    }

    // Not a player's decision (the client manager's own, cheats, or the end of the stream).
    void OnCommandSourceTerminated() override {}
    void VerifyChecksum(
      const gpg::MD5Digest&,
      moho::CSeqNo
    ) override
    {}
    void RequestPause() override {}
    void Resume() override {}
    void SingleStep() override {}
    void CreateUnit(
      uint32_t,
      const moho::RResId&,
      const moho::SCoordsVec2&,
      float
    ) override
    {}
    void CreateProp(
      const char*,
      const Wm3::Vec3f&
    ) override
    {}
    void DestroyEntity(
      moho::EntId
    ) override
    {}
    void WarpEntity(
      moho::EntId,
      const moho::VTransform&
    ) override
    {}
    void ExecuteLuaInSim(
      const char*,
      const LuaPlus::LuaObject&
    ) override
    {}
    void ExecuteDebugCommand(
      const char*,
      const Wm3::Vector3<float>&,
      uint32_t,
      const EntitySet&
    ) override
    {}
    void EndGame() override {}

  private:
    // Units are filtered to the focus army's. The count, retarget, retype and cells ops name a command, not a unit;
    // they are dropped for a command whose issue was dropped as another army's, and kept otherwise.
    [[nodiscard]] bool Foreign(
      const moho::CmdId id
    ) const
    {
      return mForeignCommands.count(static_cast<std::int32_t>(id)) != 0u;
    }

    [[nodiscard]] bool Own(
      const std::uint32_t id
    ) const noexcept
    {
      return IdArmy(id) == mArmy && IdKind(id) != kBlipKind;
    }

    [[nodiscard]] EntitySet OwnUnits(
      const EntitySet& entities
    ) const
    {
      EntitySet units{};
      entities.ForEachValue([&](const unsigned int id) {
        if (Own(id)) {
          (void)units.Add(static_cast<moho::EntId>(id));
        }
      });
      return units;
    }

    void Issue(
      const char* const op,
      const EntitySet& entities,
      const moho::SSTICommandIssueData& data,
      const bool clear
    )
    {
      if (!mOurs) {
        return;
      }
      // Only the focus army's units: a source can also command another army's (shared control).
      const EntitySet units = OwnUnits(entities);
      bool any = false;
      units.ForEachValue([&](unsigned int) {
        any = true;
      });
      if (!any) {
        // Later edits of this command (count, retarget, retype, cells) are another army's too.
        mForeignCommands.insert(data.nextCommandId);
        return;
      }
      // `nextCommandId`: the id the edit rows below name.
      std::string json = "{\"op\":\"";
      json += op;
      json += "\",\"cmd\":" + std::to_string(data.nextCommandId) + ",\"type\":";
      AppendEscaped(json, CommandTypeName(data.mCommandType));
      json += ",\"units\":";
      AppendIds(json, units);
      json += ",\"target\":";
      AppendTarget(json, data.mTarget);
      if (data.mBlueprint != nullptr) {
        json += ",\"bp\":";
        AppendEscaped(json, data.mBlueprint->mBlueprintId.c_str());
      }
      json += ",\"clear\":";
      json += clear ? '1' : '0';
      json += '}';
      Record(std::move(json), true);
    }

    void Record(
      std::string json,
      const bool checked = false
    )
    {
      if (!checked && !mOurs) {
        return;
      }
      const std::lock_guard<std::mutex> lock(mMutex);
      mCommands.emplace_back(mBeat, std::move(json));
      ++mRecorded;
    }

    std::uint32_t mArmy;
    std::vector<std::uint32_t> mSources;
    std::unordered_set<std::int32_t> mForeignCommands; // ids of issued commands that held none of the army's units
    bool mOurs = false;
    // The beat the next command runs in. The driver publishes beat 0 as its opening sync, before any Advance message
    // (CSimDriver, SimDriver.cpp: `FinalizeSyncDispatchLocked` ahead of the loop, `mDispatchBeat(1)`), and each Advance
    // then runs the next beat; so the commands before the first Advance run in beat 1, and so on.
    int mBeat = 1;
    mutable std::mutex mMutex;
    std::vector<std::pair<int, std::string>> mCommands;
    std::uint64_t mRecorded = 0;
  };

  CBotObservation::CBotObservation(
    moho::RRuleGameRules& rules,
    const int army,
    std::vector<std::uint32_t> sources,
    const int every
  )
    : mArmy(army)
    , mSources(std::move(sources))
    , mEvery(std::max(every, 1))
    , mRecorder(std::make_unique<CBotCommandRecorder>(mArmy, mSources))
    , mLuaState(new LuaPlus::LuaState(LuaPlus::LuaState::LIB_BASE))
    , mDecoder(std::make_unique<moho::CDecoder>(mRecorder.get(), mNoRecording, &rules, mLuaState.get()))
  {}

  CBotObservation::~CBotObservation()
  {
    Uninstall();
    if (mFile != nullptr) {
      std::fclose(mFile);
    }
  }

  bool CBotObservation::Open(
    const std::string& path,
    const std::string& replayPath
  )
  {
    // Binary: the same bytes, with "\n" line ends, on every platform.
    if (fopen_s(&mFile, path.c_str(), "wb") != 0) {
      mFile = nullptr;
      return false;
    }
    std::string header = "{\"format\":\"faf-bot-obs\",\"version\":3,\"replay\":";
    AppendEscaped(header, replayPath.c_str());
    header += ",\"army\":" + std::to_string(mArmy) + ",\"sources\":[";
    for (std::size_t i = 0; i < mSources.size(); ++i) {
      header += (i != 0u ? "," : "") + std::to_string(mSources[i]);
    }
    header += "],\"every\":" + std::to_string(mEvery) + "}\n";
    std::fputs(header.c_str(), mFile);
    return true;
  }

  void CBotObservation::Install()
  {
    moho::CDecoder::SetMessageObserver(&CBotObservation::Observe, this);
    mInstalled = true;
  }

  void CBotObservation::Uninstall()
  {
    if (mInstalled) {
      moho::CDecoder::SetMessageObserver(nullptr, nullptr);
      mInstalled = false;
    }
  }

  void CBotObservation::Observe(
    const moho::CMessage& message,
    void* const context
  )
  {
    static_cast<CBotObservation*>(context)->OnMessage(message);
  }

  void CBotObservation::OnMessage(
    const moho::CMessage& message
  )
  {
    if (mInside) {
      return; // this observation's own decoder
    }
    struct SInside
    {
      bool& inside;
      explicit SInside(
        bool& flag
      )
        : inside(flag)
      {
        inside = true;
      }
      ~SInside()
      {
        inside = false;
      }
    } const guard(mInside);
    // Nothing this decoder throws may reach the sim's decoder, which calls this before its own decode.
    try {
      mDecoder->ReceiveMessage(const_cast<moho::CMessage*>(&message), nullptr);
    } catch (...) {
      ++mDecodeErrors;
    }
  }

  // Visibility modes: only MapPlayableRect and ReconGrid ever show a unit. Hidden doesn't, and for any other mode
  // (0 before the entity's first update) the client keeps the mesh as it was; that is hidden here, so the view never
  // shows more than the UI.
  bool CBotObservation::TypeKnown(
    const SEntity& entity
  ) const noexcept
  {
    if (!entity.blip) {
      return true;
    }
    if (entity.visibilityMode == static_cast<std::int32_t>(moho::EUserEntityVisibilityMode::MapPlayableRect)) {
      return true;
    }
    if (entity.visibilityMode != static_cast<std::int32_t>(moho::EUserEntityVisibilityMode::ReconGrid)) {
      return false;
    }
    // As `UserUnit::UpdateVisibility` (0x008C09B0) shows the mesh.
    const std::uint32_t needed =
      entity.mobile ? static_cast<std::uint32_t>(moho::RECON_LOSNow) : static_cast<std::uint32_t>(moho::RECON_LOSEver);
    return (entity.recon & needed) != 0u;
  }

  bool CBotObservation::InSightNow(
    const SEntity& entity
  ) const noexcept
  {
    // Health shows on intel bit 0x08 whatever the visibility mode (the icon's "health-valid" bit).
    return !entity.blip || (entity.recon & static_cast<std::uint32_t>(moho::RECON_LOSNow)) != 0u;
  }

  bool CBotObservation::IconKnown(
    const SEntity& entity
  ) const noexcept
  {
    // The strategic icon picks the blueprint's own icon, and the owner's colour, on intel bit 0x10 (RECON_LOSEver),
    // mobile or not (`PickUnitStrategicIconTexture`, `PlaceUnitIcon`, CWldSessionRender.cpp); else a generic icon.
    return !entity.blip || (entity.recon & static_cast<std::uint32_t>(moho::RECON_LOSEver)) != 0u || TypeKnown(entity);
  }

  bool CBotObservation::ContactShown(
    const SEntity& entity
  ) const noexcept
  {
    const bool shownMode =
      entity.visibilityMode == static_cast<std::int32_t>(moho::EUserEntityVisibilityMode::MapPlayableRect) ||
      entity.visibilityMode == static_cast<std::int32_t>(moho::EUserEntityVisibilityMode::ReconGrid);
    if (entity.dead || !shownMode) {
      return false;
    }
    if (TypeKnown(entity)) {
      return true;
    }
    // A known fake (jammer) has its strategic icon suppressed outright (intel bit 0x20, CWldSessionRender.cpp).
    if ((entity.recon & static_cast<std::uint32_t>(moho::RECON_KnownFake)) != 0u) {
      return false;
    }
    constexpr std::uint32_t kDetectedNow = static_cast<std::uint32_t>(moho::RECON_Radar) |
      static_cast<std::uint32_t>(moho::RECON_Sonar) | static_cast<std::uint32_t>(moho::RECON_Omni) |
      static_cast<std::uint32_t>(moho::RECON_LOSNow) | static_cast<std::uint32_t>(moho::RECON_LOSEver);
    return (entity.recon & kDetectedNow) != 0u;
  }

  const char* CBotObservation::GenericClass(
    const SEntity& entity
  ) noexcept
  {
    // The generic icon (`PickGenericStrategicIconTexture`, 0x0085CBD9): structure by the blueprint's own IsMobile,
    // else by the entity's layer.
    if (!entity.blueprintMobile) {
      return "structure";
    }
    switch (entity.layer) {
    case 1:
      return "land";
    case 2:
    case 4:
    case 8:
      return "naval";
    case 16:
      return "air";
    default:
      return "other";
    }
  }

  void CBotObservation::OnPacket(
    const moho::SSyncData& packet
  )
  {
    auto addUnit = [this](const moho::SCreateEntityParams& params) {
      SEntity& entity = mEntities[params.mEntityId];
      entity = SEntity{};
      entity.blip = IdKind(params.mEntityId) == kBlipKind;
      if (params.mBlueprint != nullptr) {
        entity.blueprint = params.mBlueprint->mBlueprintId.c_str();
        // As `UserUnit::IsMobile` (0x008C04E0), which `UpdateVisibility` asks: motion types Land through
        // AmphibiousFloating move; None and Special don't (`RUnitBlueprint::IsMobile` counts Special as mobile).
        const moho::RUnitBlueprint* const unitBlueprint = params.mBlueprint->IsUnitBlueprint();
        const auto motionType =
          unitBlueprint != nullptr ? static_cast<std::uint32_t>(unitBlueprint->Physics.MotionType) : 0u;
        entity.mobile = (motionType - 1u) <= (static_cast<std::uint32_t>(moho::RULEUMT_AmphibiousFloating) - 1u);
        entity.blueprintMobile = params.mBlueprint->IsMobile();
        entity.icon = params.mBlueprint->mStrategicIconName.c_str();
      }
    };
    for (const moho::SCreateUnitParams& params : packet.mNewUnits) {
      addUnit(params);
    }

    for (const moho::SEntityVariableUpdateEntry& update : packet.mEntityUpdates) {
      const auto found = mEntities.find(static_cast<std::uint32_t>(update.mEntityId));
      if (found == mEntities.end()) {
        continue; // a prop, projectile or other plain entity: not in the view yet
      }
      const moho::SSTIEntityVariableData& data = update.mVariableData;
      SEntity& entity = found->second;
      entity.x = data.mCurTransform.pos_.x;
      entity.y = data.mCurTransform.pos_.y;
      entity.z = data.mCurTransform.pos_.z;
      entity.health = data.mHealth;
      entity.maxHealth = data.mMaxHealth;
      entity.fraction = data.mFractionComplete;
      entity.beingBuilt = data.mIsBeingBuilt != 0u;
      entity.dead = data.mIsDead != 0u;
      entity.visibilityMode = static_cast<std::int32_t>(data.mVisibilityMode);
      entity.layer = static_cast<std::int32_t>(data.mLayerMask);
    }

    for (const moho::SUnitVariableUpdateEntry& update : packet.mUnitUpdates) {
      const auto found = mEntities.find(static_cast<std::uint32_t>(update.mEntityId));
      if (found == mEntities.end()) {
        continue;
      }
      SEntity& entity = found->second;
      entity.recon = static_cast<std::uint32_t>(update.mReconFlags);
      entity.busy = update.mVariableData.mIsBusy != 0;
      entity.workProgress = update.mVariableData.mWorkProgress;
    }

    for (const moho::EntId id : packet.mDeleteIds) {
      mEntities.erase(static_cast<std::uint32_t>(id));
    }
    for (const moho::EntId id : packet.mEraseIds) {
      mEntities.erase(static_cast<std::uint32_t>(id));
    }

    if (mArmy >= 0 && static_cast<std::size_t>(mArmy) < packet.mArmyUpdates.size()) {
      const moho::SEconTotals& economy = packet.mArmyUpdates[static_cast<std::size_t>(mArmy)].mEconomyTotals;
      mEconomy = "{\"stored\":";
      AppendPair(mEconomy, economy.mStored.MASS, economy.mStored.ENERGY);
      mEconomy += ",\"income\":";
      AppendPair(mEconomy, economy.mIncome.MASS, economy.mIncome.ENERGY);
      mEconomy += ",\"requested\":";
      AppendPair(mEconomy, economy.mLastUseRequested.MASS, economy.mLastUseRequested.ENERGY);
      mEconomy += ",\"spent\":";
      AppendPair(mEconomy, economy.mLastUseActual.MASS, economy.mLastUseActual.ENERGY);
      mEconomy += ",\"max\":";
      AppendPair(
        mEconomy, static_cast<float>(economy.mMaxStorage.MASS), static_cast<float>(economy.mMaxStorage.ENERGY)
      );
      mEconomy += ",\"reclaimed\":";
      AppendPair(mEconomy, economy.mReclaimed.MASS, economy.mReclaimed.ENERGY);
      mEconomy += '}';
    }

    if (!packet.mPlayableRectUpdates.empty()) {
      const gpg::Rect2i& rect = packet.mPlayableRectUpdates.back();
      mPlayableRect = "[" + std::to_string(rect.x0) + ',' + std::to_string(rect.z0) + ',' + std::to_string(rect.x1) +
        ',' + std::to_string(rect.z1) + ']';
    }

    if (mFile != nullptr && packet.mCurBeat >= 0 && packet.mCurBeat % mEvery == 0) {
      WriteSample(packet);
    }
  }

  void CBotObservation::WriteCommands(
    const int upToBeat,
    std::string& line
  )
  {
    std::vector<std::pair<int, std::string>> commands;
    mRecorder->Take(upToBeat, commands);
    line += ",\"cmds\":[";
    for (std::size_t i = 0; i < commands.size(); ++i) {
      if (i != 0u) {
        line += ',';
      }
      // `{"b":<beat>,` in front of the command's own fields.
      line += "{\"b\":" + std::to_string(commands[i].first) + ',';
      line.append(commands[i].second, 1u, std::string::npos);
    }
    line += ']';
    mCommandsWritten += commands.size();
  }

  void CBotObservation::WriteSample(
    const moho::SSyncData& packet
  )
  {
    std::vector<std::pair<std::uint32_t, const SEntity*>> sorted;
    sorted.reserve(mEntities.size());
    for (const auto& [id, entity] : mEntities) {
      sorted.emplace_back(id, &entity);
    }
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) {
      return a.first < b.first;
    });

    std::string line = "{\"beat\":" + std::to_string(packet.mCurBeat) + ",\"tick\":" + std::to_string(packet.mCurTick);
    if (!mPlayableRect.empty()) {
      line += ",\"rect\":" + mPlayableRect;
      mPlayableRect.clear();
    }
    if (!mEconomy.empty()) {
      line += ",\"eco\":" + mEconomy;
    }

    // Own units: [id, bp, x, y, z, health, maxHealth, fraction, busy, work]
    line += ",\"own\":[";
    bool first = true;
    for (const auto& [id, entity] : sorted) {
      if (entity->blip || entity->dead || IdArmy(id) != static_cast<std::uint32_t>(mArmy)) {
        continue;
      }
      line += first ? "[" : ",[";
      first = false;
      line += std::to_string(id) + ',';
      AppendEscaped(line, entity->blueprint.c_str());
      for (const float value : {entity->x, entity->y, entity->z, entity->health, entity->maxHealth}) {
        line += ',';
        AppendFloat(line, value);
      }
      char tail[64];
      std::snprintf(
        tail,
        sizeof(tail),
        ",%.2f,%d,%.2f]",
        static_cast<double>(entity->fraction),
        entity->busy ? 1 : 0,
        static_cast<double>(entity->workProgress)
      );
      line += tail;
      ++mOwnRows;
    }

    // Contacts (other armies' units as this player's UI shows them):
    // [id, bp or null, icon or null, generic class, x, y, z, recon flags, health or null, maxHealth or null,
    //  army or null]: the three levels the UI shows. The generic icon's class always; the unit's own strategic icon
    // and owner once seen (0x10); the mesh, and so the exact blueprint, by `UserUnit::UpdateVisibility`.
    line += "],\"contacts\":[";
    first = true;
    for (const auto& [id, entity] : sorted) {
      const bool otherArmyUnit = !entity->blip && IdArmy(id) != static_cast<std::uint32_t>(mArmy);
      if ((!entity->blip && !otherArmyUnit) || !ContactShown(*entity)) {
        continue;
      }
      const bool known = TypeKnown(*entity);
      const bool iconKnown = IconKnown(*entity);
      line += first ? "[" : ",[";
      first = false;
      line += std::to_string(id) + ',';
      if (known) {
        AppendEscaped(line, entity->blueprint.c_str());
      } else {
        line += "null";
      }
      line += ',';
      if (iconKnown) {
        AppendEscaped(line, entity->icon.c_str());
      } else {
        line += "null";
      }
      line += ',';
      AppendEscaped(line, GenericClass(*entity));
      for (const float value : {entity->x, entity->y, entity->z}) {
        line += ',';
        AppendFloat(line, value);
      }
      // The recon flags, plus kShownMapWide when the entity's visibility mode is MapPlayableRect: the UI then draws
      // its mesh whatever the intel (`UserUnit::UpdateVisibility`), as for civilians revealed at the start.
      std::uint32_t flags = entity->recon;
      if (entity->visibilityMode == static_cast<std::int32_t>(moho::EUserEntityVisibilityMode::MapPlayableRect)) {
        flags |= kShownMapWide;
      }
      line += ',' + std::to_string(flags) + ',';
      // Health only while in sight now: a structure remembered from an earlier sighting
      // (RECON_LOSEver alone) keeps its type and owner, not its live health.
      if (known && InSightNow(*entity)) {
        AppendFloat(line, entity->health);
        line += ',';
        AppendFloat(line, entity->maxHealth);
      } else {
        line += "null,null";
      }
      line += iconKnown ? ',' + std::to_string(IdArmy(id)) : std::string(",null");
      line += ']';
      ++mContactRows;
      if (known) {
        ++mKnownContactRows;
      }
      if (iconKnown) {
        ++mIconContactRows;
      }
    }
    line += ']';

    WriteCommands(packet.mCurBeat, line);
    line += "}\n";
    std::fputs(line.c_str(), mFile);
    ++mSamples;
  }

  void CBotObservation::Finish()
  {
    // The observer stays installed: the sim's thread may still be decoding, and the observer and its context are set
    // one after the other. The destructor takes it out, after the driver (declared later) has stopped that thread.
    if (mFile == nullptr) {
      return;
    }
    std::string line = "{\"end\":true";
    WriteCommands(INT32_MAX, line);
    line += "}\n";
    std::fputs(line.c_str(), mFile);
    std::fclose(mFile);
    mFile = nullptr;
  }

  std::string CBotObservation::Summary() const
  {
    return "bot-obs: army " + std::to_string(mArmy) + ", " + std::to_string(mSamples) + " samples, " +
      std::to_string(mOwnRows) + " own-unit rows, " + std::to_string(mContactRows) + " contact rows (" +
      std::to_string(mKnownContactRows) + " with blueprint, " + std::to_string(mIconContactRows) + " with icon), " +
      std::to_string(mRecorder->Recorded()) + " commands recorded, " + std::to_string(mCommandsWritten) + " written, " +
      std::to_string(mDecodeErrors.load()) + " decode errors";
  }
} // namespace faf::headless
