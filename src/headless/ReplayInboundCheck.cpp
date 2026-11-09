#include "headless/ReplayInboundCheck.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "gpg/core/streams/Stream.h"
#include "lua/LuaObject.h"
#include "lua/LuaTableIterator.h"
#include "moho/entity/EntityDb.h"
#include "moho/misc/CDecoder.h"
#include "moho/net/CMessage.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/Sim.h"
#include "remote/VisibilityOracle.h"

// Engine addition, server mode: see ReplayInboundCheck.h.

namespace faf::headless
{
  namespace
  {
    constexpr std::size_t kNamedExamples = 8;

    [[nodiscard]] std::vector<char> MessageBytes(const moho::CMessage& message)
    {
      return std::vector<char>(message.mBuff.start_, message.mBuff.start_ + message.mBuff.Size());
    }
  } // namespace

  CReplayInboundCheck::CReplayInboundCheck(moho::RRuleGameRules& rules, const remote::CViewFrames& views)
    : mViews(views)
    , mLuaState(new LuaPlus::LuaState(LuaPlus::LuaState::LIB_BASE))
    , mCapture([this](moho::CMessage& message) { mCaptured.push_back(MessageBytes(message)); }, nullptr)
    , mMarshaller(std::make_unique<moho::CMarshaller>(&mCapture))
    , mTranslator(*mMarshaller, mNoMap)
    , mClient(mTranslator, *this)
    , mPlainDecoder(std::make_unique<moho::CDecoder>(mMarshaller.get(), mNoRecording, &rules, mLuaState.get()))
    , mIdDecoder(std::make_unique<moho::CDecoder>(&mClient, mNoRecording, &rules, mLuaState.get()))
  {}

  CReplayInboundCheck::~CReplayInboundCheck()
  {
    Uninstall();
  }

  void CReplayInboundCheck::Install()
  {
    moho::CDecoder::SetMessageObserver(&CReplayInboundCheck::Observe, this);
  }

  void CReplayInboundCheck::Uninstall()
  {
    moho::CDecoder::SetMessageObserver(nullptr, nullptr);
  }

  void CReplayInboundCheck::Observe(const moho::CMessage& message, void* const context)
  {
    static_cast<CReplayInboundCheck*>(context)->OnMessage(message);
  }

  void CReplayInboundCheck::SelectSource(const moho::CommandSourceId sourceId)
  {
    // The source's army: the one whose valid command sources list it (`CArmyImpl` keeps them).
    mArmy = -1;
    const moho::Sim* const sim = mViews.LastSim();
    if (sim != nullptr) {
      for (std::size_t index = 0; index < sim->mArmiesList.size(); ++index) {
        const moho::CArmyImpl* const army = sim->mArmiesList[index];
        if (army != nullptr && army->mVarDat.mValidCommandSources.Contains(static_cast<unsigned int>(sourceId))) {
          mArmy = static_cast<std::int32_t>(index);
          break;
        }
      }
    }
    if (mArmy >= 0 && static_cast<std::size_t>(mArmy) < mViews.ViewCount()) {
      mTranslator.SetMap(mViews.IdMap(mArmy));
    } else {
      mTranslator.SetMap(mNoMap);
    }
  }

  bool CReplayInboundCheck::IsOwnCommand(const std::uint32_t commandId) const
  {
    const moho::Sim* const sim = mViews.LastSim();
    if (sim == nullptr || mArmy < 0 || static_cast<std::size_t>(mArmy) >= sim->mArmiesList.size()) {
      return false;
    }
    const moho::CArmyImpl* const army = sim->mArmiesList[static_cast<std::size_t>(mArmy)];
    return army != nullptr && army->mVarDat.mValidCommandSources.Contains(commandId >> 24u);
  }

  void CReplayInboundCheck::CClientSide::SetCommandSource(const moho::CommandSourceId sourceId)
  {
    mOwner.SelectSource(sourceId);
    CCommandIdRewriter::SetCommandSource(sourceId);
  }

  void CReplayInboundCheck::CClientSide::LuaSimCallback(
    const char* const name, const LuaPlus::LuaObject& args, const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities
  )
  {
    if (mOwner.mViews.LastSim() != nullptr && name != nullptr) {
      ++mOwner.mCallbacks[name];
      mOwner.AuditPayload(name, args, "args", 0);
    }
    CCommandIdRewriter::LuaSimCallback(name, args, entities);
  }

  void CReplayInboundCheck::AuditPayload(
    const std::string& callback, const LuaPlus::LuaObject& value, const std::string& path, const int depth
  )
  {
    if (depth > 8) {
      return;
    }
    if (value.IsTable()) {
      for (LuaPlus::LuaTableIterator it(value, 1); it.IsValid(); it.Next()) {
        LuaPlus::LuaObject& key = it.GetKey();
        std::string child = path;
        if (key.IsString()) {
          child += ".";
          child += key.GetString();
        } else {
          child += "[]"; // array positions are one key: the same field in every element
        }
        AuditPayload(callback, it.GetValue(), child, depth + 1);
      }
      return;
    }
    if (value.IsNumber()) {
      AuditValue(callback, path, value.GetNumber());
    } else if (value.IsString()) {
      const char* const text = value.GetString();
      if (text != nullptr && *text != '\0' && std::strspn(text, "0123456789") == std::strlen(text) && std::strlen(text) <= 10u) {
        AuditValue(callback, path + "(string)", std::strtod(text, nullptr));
      }
    }
  }

  void CReplayInboundCheck::AuditValue(const std::string& callback, const std::string& path, const double number)
  {
    if (number < 0.0 || number > 4294967295.0 || number != std::floor(number)) {
      return;
    }
    const moho::Sim* const sim = mViews.LastSim();
    if (sim == nullptr || sim->mEntityDB == nullptr) {
      return;
    }
    const auto id = static_cast<std::uint32_t>(number);
    const auto found = sim->mEntityDB->mAllUnits.find(id);
    if (found == sim->mEntityDB->mAllUnits.end() || found->second == nullptr) {
      return; // not an entity the sim has
    }
    SPayloadIds& ids = mPayloadIds[{callback, path}];
    if (ids.own + ids.blips + ids.foreign == 0u) {
      ids.example = id;
    }
    if ((id >> 28u) == 3u) {
      ++ids.blips;
    } else if (mArmy >= 0 && ((id >> 20u) & 0xFFu) == static_cast<std::uint32_t>(mArmy)) {
      ++ids.own;
    } else {
      ++ids.foreign;
    }
  }

  bool CReplayInboundCheck::CClientSide::RewriteEntity(std::uint32_t& id)
  {
    mOwner.mLastRefused = id;
    if (mOwner.mArmy < 0 || static_cast<std::size_t>(mOwner.mArmy) >= mOwner.mViews.ViewCount()) {
      return !mOwner.mNoMap.MapsEntity(id); // no view: only ids that are never renumbered go through
    }
    return mOwner.mViews.IdMap(mOwner.mArmy).EntityToHeldView(id, id);
  }

  bool CReplayInboundCheck::CClientSide::RewriteCommand(std::uint32_t& id)
  {
    if (mOwner.mArmy < 0 || static_cast<std::size_t>(mOwner.mArmy) >= mOwner.mViews.ViewCount()) {
      return false;
    }
    const auto own = [this](const std::uint32_t commandId) { return mOwner.IsOwnCommand(commandId); };
    return mOwner.mViews.IdMap(mOwner.mArmy).CommandToHeldView(id, own, id);
  }

  void CReplayInboundCheck::OnMessage(const moho::CMessage& message)
  {
    if (mInside) {
      return; // this check's own decoders
    }
    struct SInside
    {
      bool& inside;
      explicit SInside(bool& flag) : inside(flag) { inside = true; }
      ~SInside() { inside = false; }
    };
    ++mMessages;
    if (mViews.ViewCount() == 0u || !mViews.IdMapsOn()) {
      ++mBeforeViews;
      // Both decoders still follow the stream (the source, the Lua state), as on every message.
      const SInside guard(mInside);
      mCaptured.clear();
      mPlainDecoder->ReceiveMessage(const_cast<moho::CMessage*>(&message), nullptr);
      mIdDecoder->ReceiveMessage(const_cast<moho::CMessage*>(&message), nullptr);
      return;
    }

    // The sim's decoder calls this on the sim thread, one message at a time, as the views do.
    const SInside guard(mInside);
    mCaptured.clear();
    mPlainDecoder->ReceiveMessage(const_cast<moho::CMessage*>(&message), nullptr);
    const std::vector<std::vector<char>> plain = std::move(mCaptured);

    mCaptured.clear();
    const std::uint64_t droppedBefore = mClient.Dropped();
    mIdDecoder->ReceiveMessage(const_cast<moho::CMessage*>(&message), nullptr);
    if (mClient.Dropped() != droppedBefore) {
      ++mNotShown;
      if (mNotShownExamples.size() < kNamedExamples) {
        const moho::Sim* const sim = mViews.LastSim();
        // Why: when the view's map retired the id, whether the sim still has the entity and lets
        // this view have it now, and which other views were given it.
        const std::uint32_t id = mLastRefused;
        std::string why;
        std::uint32_t retired = 0;
        if (mArmy >= 0 && static_cast<std::size_t>(mArmy) < mViews.ViewCount() && mViews.IdMap(mArmy).RetiredAt(id, retired)) {
          why += " retired at beat " + std::to_string(retired) + ";";
        } else {
          why += " never in this view's map;";
        }
        moho::Entity* entity = nullptr;
        if (sim != nullptr && sim->mEntityDB != nullptr) {
          const auto found = sim->mEntityDB->mAllUnits.find(id);
          entity = found != sim->mEntityDB->mAllUnits.end() ? found->second : nullptr;
        }
        if (entity == nullptr) {
          why += " the sim no longer has it;";
        } else if (mArmy >= 0) {
          why += remote::ResolveViewVisibility(*sim, mArmy, *entity).published ? " published to this view" : " not published to this view";
          why += remote::CanViewSee(*sim, mArmy, *entity) ? ", seen;" : ", not seen;";
        }
        std::string others;
        for (std::size_t view = 0; view < mViews.ViewCount(); ++view) {
          std::uint32_t viewId = 0;
          if (static_cast<std::int32_t>(view) != mArmy && mViews.IdMap(static_cast<std::int32_t>(view)).EntityToView(id, viewId)) {
            others += (others.empty() ? " held by views " : ",") + std::to_string(view);
          }
        }
        char text[384];
        std::snprintf(
          text, sizeof(text), "beat %d, army %d: %s;%s%s", sim != nullptr ? static_cast<int>(sim->mCurBeat) : -1, mArmy,
          mClient.LastDrop().c_str(), why.c_str(), others.c_str()
        );
        mNotShownExamples.emplace_back(text);
      }
      return;
    }
    if (mCaptured == plain) {
      ++mIdentical;
    } else {
      ++mDiffering;
    }
  }

  std::string CReplayInboundCheck::Summary() const
  {
    char text[512];
    std::snprintf(
      text, sizeof(text),
      "inbound check: %llu messages, %llu before the first views; %llu identical after view ids and back "
      "(%llu ids rewritten to view ids, %llu translated back), %llu differing, %llu naming a renumbered id "
      "their view was never given; translator drops %llu",
      static_cast<unsigned long long>(mMessages), static_cast<unsigned long long>(mBeforeViews),
      static_cast<unsigned long long>(mIdentical), static_cast<unsigned long long>(mClient.IdsRewritten()),
      static_cast<unsigned long long>(mTranslator.IdsRewritten()), static_cast<unsigned long long>(mDiffering),
      static_cast<unsigned long long>(mNotShown), static_cast<unsigned long long>(mTranslator.Dropped())
    );
    std::string summary = text;
    // Plan WP5.12: orders on blips the server passed on to the sim, in sim ids, after view ids.
    using Type = moho::EUnitCommandType;
    std::uint64_t otherBlipTargets = 0;
    for (std::size_t type = 0; type < 64u; ++type) {
      const auto commandType = static_cast<Type>(type);
      if (commandType != Type::UNITCOMMAND_Attack && commandType != Type::UNITCOMMAND_FormAttack
          && commandType != Type::UNITCOMMAND_Guard && commandType != Type::UNITCOMMAND_Reclaim
          && commandType != Type::UNITCOMMAND_Capture) {
        otherBlipTargets += mTranslator.BlipTargets(commandType);
      }
    }
    std::snprintf(
      text, sizeof(text),
      "\n  orders on blips through view ids: attack %llu, formation attack %llu, guard %llu, reclaim %llu, "
      "capture %llu, other %llu",
      static_cast<unsigned long long>(mTranslator.BlipTargets(Type::UNITCOMMAND_Attack)),
      static_cast<unsigned long long>(mTranslator.BlipTargets(Type::UNITCOMMAND_FormAttack)),
      static_cast<unsigned long long>(mTranslator.BlipTargets(Type::UNITCOMMAND_Guard)),
      static_cast<unsigned long long>(mTranslator.BlipTargets(Type::UNITCOMMAND_Reclaim)),
      static_cast<unsigned long long>(mTranslator.BlipTargets(Type::UNITCOMMAND_Capture)),
      static_cast<unsigned long long>(otherBlipTargets)
    );
    summary += text;
    std::snprintf(
      text, sizeof(text), "\n  callback values outside the marked fields that are ids the view was given: %llu",
      static_cast<unsigned long long>(mTranslator.UnmarkedIds())
    );
    summary += text;
    for (const std::string& example : mNotShownExamples) {
      summary += "\n  never given: " + example;
    }
    // Plan WPR.19: entity ids inside sim callbacks' Lua arguments.
    std::uint64_t calls = 0;
    for (const auto& [name, count] : mCallbacks) {
      calls += count;
    }
    std::snprintf(
      text, sizeof(text), "\n  sim callbacks: %llu calls, %zu names; Lua arguments that name an entity the sim has:",
      static_cast<unsigned long long>(calls), mCallbacks.size()
    );
    summary += text;
    if (mPayloadIds.empty()) {
      summary += " none";
    }
    for (const auto& [where, ids] : mPayloadIds) {
      std::snprintf(
        text, sizeof(text), "\n    %s %s: own %llu, blips %llu, foreign %llu (first 0x%08x; %llu calls)", where.first.c_str(),
        where.second.c_str(), static_cast<unsigned long long>(ids.own), static_cast<unsigned long long>(ids.blips),
        static_cast<unsigned long long>(ids.foreign), ids.example,
        static_cast<unsigned long long>(mCallbacks.count(where.first) != 0u ? mCallbacks.at(where.first) : 0u)
      );
      summary += text;
    }
    return summary;
  }
} // namespace faf::headless
