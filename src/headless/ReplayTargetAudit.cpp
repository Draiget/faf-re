#include "headless/ReplayTargetAudit.h"

#include <cstdio>

#include "gpg/core/streams/Stream.h"
#include "lua/LuaObject.h"
#include "moho/misc/CDecoder.h"
#include "moho/net/CMessage.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/Sim.h"
#include "remote/ViewFrames.h"

// Engine addition, dedicated server: see ReplayTargetAudit.h.

namespace faf::headless
{
  namespace
  {
    constexpr std::uint32_t kNamedExamples = 12;
  } // namespace

  CReplayTargetAudit::CReplayTargetAudit(moho::RRuleGameRules& rules, remote::CViewFrames& views)
    : mViews(views)
    , mLuaState(new LuaPlus::LuaState(LuaPlus::LuaState::LIB_BASE))
    , mCapture([](moho::CMessage&) {}, nullptr)
    , mMarshaller(std::make_unique<moho::CMarshaller>(&mCapture))
    , mSink(*mMarshaller, *this)
    , mDecoder(std::make_unique<moho::CDecoder>(&mSink, mNoRecording, &rules, mLuaState.get()))
  {}

  CReplayTargetAudit::~CReplayTargetAudit()
  {
    Uninstall();
  }

  void CReplayTargetAudit::Install()
  {
    moho::CDecoder::SetMessageObserver(&CReplayTargetAudit::Observe, this);
  }

  void CReplayTargetAudit::Uninstall()
  {
    moho::CDecoder::SetMessageObserver(nullptr, nullptr);
  }

  void CReplayTargetAudit::Observe(const moho::CMessage& message, void* const context)
  {
    static_cast<CReplayTargetAudit*>(context)->OnMessage(message);
  }

  void CReplayTargetAudit::OnMessage(const moho::CMessage& message)
  {
    if (mInside) {
      return; // this audit's own decoder
    }
    mInside = true;
    mDecoder->ReceiveMessage(const_cast<moho::CMessage*>(&message), nullptr);
    mInside = false;
  }

  void CReplayTargetAudit::CSink::SetCommandSource(const moho::CommandSourceId sourceId)
  {
    mOwner.mArmy = -1;
    if (const moho::Sim* const sim = mOwner.mViews.LastSim(); sim != nullptr) {
      for (std::size_t index = 0; index < sim->mArmiesList.size(); ++index) {
        const moho::CArmyImpl* const army = sim->mArmiesList[index];
        if (army != nullptr && army->mVarDat.mValidCommandSources.Contains(static_cast<unsigned int>(sourceId))) {
          mOwner.mArmy = static_cast<std::int32_t>(index);
          break;
        }
      }
    }
    CCommandIdRewriter::SetCommandSource(sourceId);
  }

  bool CReplayTargetAudit::CSink::AllowTarget(const std::uint32_t id)
  {
    mOwner.NoteTarget(id);
    return true;
  }

  void CReplayTargetAudit::NoteTarget(const std::uint32_t id)
  {
    if (mArmy < 0 || static_cast<std::size_t>(mArmy) >= mViews.ViewCount()) {
      return;
    }
    // The sim thread, in its beat; the last beat's views may be going on.
    (void)mViews.FinishViews();
    if (mViews.IdMap(mArmy).MapsEntity(id)) {
      ++mRenumbered;
      return;
    }
    const std::size_t family = id >> 28u;
    if (mViews.ViewHoldsEntity(static_cast<std::size_t>(mArmy), id)) {
      ++mHeld[family];
      return;
    }
    ++mNotHeld[family];
    if (mExampleCount < kNamedExamples) {
      ++mExampleCount;
      char text[96];
      const moho::Sim* const sim = mViews.LastSim();
      std::snprintf(text, sizeof(text), " [army %d named %08x at beat %u]", mArmy, id, sim != nullptr ? sim->mCurBeat : 0u);
      mExamples += text;
    }
  }

  std::string CReplayTargetAudit::Summary() const
  {
    std::string line = "targets named: " + std::to_string(mRenumbered) + " renumbered;";
    for (std::size_t family = 0; family < kFamilies; ++family) {
      if (mHeld[family] + mNotHeld[family] != 0u) {
        line += " family " + std::to_string(family) + ": " + std::to_string(mHeld[family]) + " held, " + std::to_string(mNotHeld[family]) + " not;";
      }
    }
    return line + mExamples;
  }
} // namespace faf::headless
