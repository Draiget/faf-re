#include "remote/client/NetworkSimDriver.h"
#include "remote/FocusAndCameras.h"
#include "moho/render/camera/GeomCamera3.h"
#include "remote/SpeedLimit.h"
#include "remote/client/ServerLaneMeter.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <optional>
#include <utility>

#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/console/CConCommand.h"
#include "moho/render/camera/VTransform.h"
#include "moho/lua/SCR_String.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/resource/CSimResources.h"
#include "moho/net/CMessage.h"
#include "moho/net/CMessageStream.h"
#include "moho/net/ELobbyMsg.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SSTIArmyConstantData.h"
#include "moho/sim/SSTIArmyVariableData.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/SimDriver.h"
#include "remote/ArmyRecords.h"
#include "moho/net/IClientMgrUIInterface.h"
#include "remote/SeatRoster.h"
#include "remote/client/ServerConnect.h"
#include "remote/net/Datagram.h"
#include "remote/net/GameLinks.h"
#include "remote/wire/BitStream.h"
#include "remote/wire/LuaSyncLane.h"

// Engine addition, server mode: see NetworkSimDriver.h.

namespace faf::remote::client
{
  namespace
  {
    constexpr std::uint32_t kSummaryEveryViews = 600; // one minute of game time

    // Plan WP10.9, WPR.14: the view buffer's switches (docs/SWITCHES.md, server mode), read live. They change only
    // when this client shows what the server sent, never what it sends or what any sim computes.
    std::int32_t net_ClientInterp = 1;
    std::int32_t net_ClientInterpAdaptive = 1;
    std::int32_t net_ClientInterpTicks = 1;
    std::int32_t net_ClientInterpMaxTicks = 10;
    std::int32_t net_ClientExtrapolateBeats = 2;

    moho::TConVar<std::int32_t> gTConVar_net_ClientInterp(
      "net_ClientInterp",
      "Server-mode games: 1 (default) keeps the display a few beats behind the server's views and makes up a beat "
      "that comes late; 0 shows each view as it comes.",
      &net_ClientInterp
    );
    moho::TConVar<std::int32_t> gTConVar_net_ClientInterpAdaptive(
      "net_ClientInterpAdaptive",
      "Server-mode games: 1 (default) sizes the view buffer from how late the views come; 0 keeps it at "
      "net_ClientInterpTicks.",
      &net_ClientInterpAdaptive
    );
    moho::TConVar<std::int32_t> gTConVar_net_ClientInterpTicks(
      "net_ClientInterpTicks",
      "Server-mode games: the fewest beats the view buffer keeps (default 1).",
      &net_ClientInterpTicks
    );
    moho::TConVar<std::int32_t> gTConVar_net_ClientInterpMaxTicks(
      "net_ClientInterpMaxTicks",
      "Server-mode games: the most beats the adaptive view buffer keeps (default 10).",
      &net_ClientInterpMaxTicks
    );
    moho::TConVar<std::int32_t> gTConVar_net_ClientExtrapolateBeats(
      "net_ClientExtrapolateBeats",
      "Server-mode games: beats past the last view the display may make up while the next is late, carrying moving "
      "entities on (default 2; 0 waits instead).",
      &net_ClientExtrapolateBeats
    );

    [[nodiscard]] double NowSeconds() noexcept
    {
      return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
    }

    [[nodiscard]] SSynthTransform ToSynth(
      const moho::VTransform& transform
    ) noexcept
    {
      SSynthTransform out;
      out.px = transform.pos_.x;
      out.py = transform.pos_.y;
      out.pz = transform.pos_.z;
      out.qw = transform.orient_.w;
      out.qx = transform.orient_.x;
      out.qy = transform.orient_.y;
      out.qz = transform.orient_.z;
      return out;
    }

    void FromSynth(
      const SSynthTransform& transform,
      moho::VTransform& out
    ) noexcept
    {
      out.pos_.x = transform.px;
      out.pos_.y = transform.py;
      out.pos_.z = transform.pz;
      out.orient_.w = transform.qw;
      out.orient_.x = transform.qx;
      out.orient_.y = transform.qy;
      out.orient_.z = transform.qz;
    }

    /** The client's real data of a live entity, as the session was last given it. */
    [[nodiscard]] CBeatSynthesizer::Lookup HeldLookup(
      const CSyncRebuilder& rebuilder
    )
    {
      return [&rebuilder](const std::uint32_t id, SSynthTransform& last, SSynthTransform& cur) {
        CSyncRebuilder::SHeldView held;
        if (!rebuilder.FindHeld(id, false, held) || held.data == nullptr) {
          return false;
        }
        last = ToSynth(held.data->mLastTransform);
        cur = ToSynth(held.data->mCurTransform);
        return true;
      };
    }

    /** A packet's entity updates as transforms, in its order. */
    [[nodiscard]] std::vector<SSynthUpdate> UpdatesOf(
      const moho::SSyncData& packet
    )
    {
      std::vector<SSynthUpdate> out;
      out.reserve(packet.mEntityUpdates.size());
      for (const moho::SEntityVariableUpdateEntry& entry : packet.mEntityUpdates) {
        SSynthUpdate update;
        update.id = static_cast<std::uint32_t>(entry.mEntityId);
        update.last = ToSynth(entry.mVariableData.mLastTransform);
        update.cur = ToSynth(entry.mVariableData.mCurTransform);
        out.push_back(update);
      }
      return out;
    }

    /** The bytes `LuaObject::ToByteStream` writes for an empty table: a beat whose Lua lane carries nothing. */
    [[nodiscard]] std::vector<std::uint8_t> EmptyTableBytes(
      LuaPlus::LuaState& state
    )
    {
      LuaPlus::LuaObject table;
      table.AssignNewTable(&state, 0, 0u);
      // As the server writes its tables (ServerMain's MakeLaunchInfo): into a message, then its payload.
      moho::CMessage message(moho::ELobbyMsg::LOBMSG_DirectScriptData);
      {
        moho::CMessageStream stream(message, moho::CMessageStream::Access::kReadWrite);
        (void)table.ToByteStream(stream);
      }
      constexpr std::size_t kHeaderBytes = 3u;
      const auto* const bytes = reinterpret_cast<const std::uint8_t*>(message.mBuff.start_);
      const std::size_t size = message.mBuff.Size();
      return size > kHeaderBytes ? std::vector<std::uint8_t>(bytes + kHeaderBytes, bytes + size)
                                 : std::vector<std::uint8_t>{};
    }
  } // namespace

  /**
   * Plan WP10.9: what a made-up beat repeats of the last real packet, as the session sets them from every packet:
   * the focus, fog and pause flags, and the height field and deposits it keeps a reference to. (The views carry no
   * `mSyncExtraUnitData`: every packet here has it empty, and a made-up one too.)
   */
  struct CNetworkSimDriver::SCarried
  {
    std::int32_t focusArmy = -1;
    bool fogOfWar = false;
    std::int32_t pausedBy = -1;
    boost::SharedPtrRaw<moho::CHeightField> terrain;
    boost::SharedPtrRaw<moho::CSimResources> resources;

    SCarried() = default;
    SCarried(const SCarried&) = delete;
    SCarried& operator=(const SCarried&) = delete;
    ~SCarried()
    {
      terrain.release();
      resources.release();
    }
  };

  CNetworkSimDriver::CNetworkSimDriver(
    moho::RRuleGameRules& rules,
    const moho::LaunchInfoBase& launch,
    const char* const playerName,
    const int clientIndex,
    const std::int32_t uid,
    const unsigned int sourceId,
    const moho::CHeightField* const heights
  )
    : mRules(rules)
    , mClientManager(
        [this](moho::CMessage& message) {
          SendCommandFrame(message);
        },
        nullptr
      )
    , mMarshaller(&mClientManager)
    , mEmptySyncLua(new LuaPlus::LuaState(LuaPlus::LuaState::LIB_BASE))
    , mCarried(std::make_unique<SCarried>())
  {
    ConfigureBuffer();
    mEmptySync = EmptyTableBytes(*mEmptySyncLua);
    mResources.reset(new moho::CSimResources());
    mSeedHeights = heights;
    // The armies, as `CArmyImpl`'s constructor names them from each army's setup (0x006FE690: `ArmyName`,
    // `PlayerName`, `Civilian`); their intel grids stay null, which user code reads as unknown (research WP11.3).
    if (const auto* const launchNew = dynamic_cast<const moho::LaunchInfoNew*>(&launch); launchNew != nullptr) {
      for (std::size_t index = 0; index < launchNew->mStrVec.size(); ++index) {
        moho::SSTIArmyConstantData army{};
        army.mArmyIndex = static_cast<std::int32_t>(index);
        try {
          LuaPlus::LuaObject setup;
          (void)moho::SCR_FromString(&setup, launchNew->mStrVec[index], mEmptySyncLua.get());
          if (setup.IsTable()) {
            const LuaPlus::LuaObject armyName = setup["ArmyName"];
            const LuaPlus::LuaObject playerName = setup["PlayerName"];
            const LuaPlus::LuaObject civilian = setup["Civilian"];
            army.mArmyName.assign_owned(armyName.IsString() ? armyName.GetString() : "");
            army.mPlayerName.assign_owned(playerName.IsString() ? playerName.GetString() : "");
            army.mIsCivilian = static_cast<std::uint8_t>(civilian.IsBoolean() && civilian.GetBoolean() ? 1u : 0u);
          }
        } catch (const std::exception& error) {
          gpg::Warnf("server driver: army %zu's setup doesn't read: %s", index, error.what());
        }
        mArmyConstants.push_back(army);
      }
    }
    mAvailable = ::CreateEventW(nullptr, TRUE, FALSE, nullptr); // manual reset: set while packets wait
    (void)mClientManager.CreateLocalClient(playerName, clientIndex, uid, sourceId);
    mClientManager.SetLoadedHandler([] {
      const std::uint8_t loaded = static_cast<std::uint8_t>(net::ESeatMessage::Loaded);
      (void)SendServerGameMessage(std::span<const std::uint8_t>(&loaded, 1u));
      gpg::Logf("server driver: loaded; told the server");
    });
    gpg::Logf(
      "server driver: on, as client %d (uid %d, source %u), %zu armies",
      clientIndex,
      static_cast<int>(uid),
      sourceId,
      mArmyConstants.size()
    );
  }

  CNetworkSimDriver::~CNetworkSimDriver()
  {
    LogSummary("end");
    if (mAvailable != nullptr) {
      (void)::CloseHandle(mAvailable);
    }
  }

  void CNetworkSimDriver::LogSummary(
    const char* const when
  ) const
  {
    const SServerViewStats noStats{};
    const SServerViewStats& views = mViews ? mViews->Stats() : noStats;
    gpg::Logf(
      "server driver %s: %llu views (%llu applied, %llu bad, %llu frame failures), beat %d, %llu commands sent, "
      "answers %llu applied / "
      "%llu refused / %llu dropped (issue lead %d beats, largest %d, %llu applied past their beat), %llu Lua lanes "
      "bad, "
      "%llu without their LuaSync; session tables: %llu records (%llu bad, %llu resets), "
      "%zu deposits, %llu terrain edits, %llu unknown ids; clock: server rate %+d, %.1f beats/s on its clock, %.1f "
      "arriving, "
      "backlog %lld, skew %.2f; roster: %llu (%llu bad), %zu clients; chat: %llu sent, %llu received, %llu bad; "
      "KB by lane: entities %.0f, armies %.0f, grids %.0f, Lua %.0f, poses %.0f, effects %.0f",
      when,
      static_cast<unsigned long long>(mViewsTaken),
      static_cast<unsigned long long>(views.applied),
      static_cast<unsigned long long>(mViewsBad),
      static_cast<unsigned long long>(views.frameFailures),
      static_cast<int>(mLastBeat),
      static_cast<unsigned long long>(mCommandsSent),
      static_cast<unsigned long long>(mAnswers[0]),
      static_cast<unsigned long long>(mAnswers[1]),
      static_cast<unsigned long long>(mAnswers[2]),
      static_cast<int>(mIssueLead),
      static_cast<int>(mLargestLead),
      static_cast<unsigned long long>(mAnswersPastEstimate),
      static_cast<unsigned long long>(mLuaLanesBad),
      static_cast<unsigned long long>(mLuaMissing),
      static_cast<unsigned long long>(views.tableRecords),
      static_cast<unsigned long long>(views.tableFailures + mTablesBad),
      static_cast<unsigned long long>(views.tableResets),
      mViews ? mViews->Tables().Deposits().size() : std::size_t{0},
      static_cast<unsigned long long>(mViews ? mViews->RebuildStats().terrainEdits : 0u),
      static_cast<unsigned long long>(mViews ? mViews->RebuildStats().unknownTableIds : 0u),
      static_cast<int>(mClock.ServerSimRate()),
      mClock.ServerBeatsPerSecond(),
      mClock.ArrivalBeatsPerSecond(),
      static_cast<long long>(mClock.Backlog()),
      mClock.Skew(),
      static_cast<unsigned long long>(mRosters),
      static_cast<unsigned long long>(mRostersBad),
      mClientManager.RosterCount(),
      static_cast<unsigned long long>(mChatSent),
      static_cast<unsigned long long>(mChatReceived),
      static_cast<unsigned long long>(mChatBad),
      static_cast<double>(mLaneBytes[0]) / 1024.0,
      static_cast<double>(mLaneBytes[1]) / 1024.0,
      static_cast<double>(mLaneBytes[2]) / 1024.0,
      static_cast<double>(mLaneBytes[3]) / 1024.0,
      static_cast<double>(mLaneBytes[4]) / 1024.0,
      static_cast<double>(mLaneBytes[5]) / 1024.0
    );
    // Plan WP10.9, WPR.14: the view buffer: its depth, the views' lateness, and what late views cost the display.
    const SInterpStats& buffer = mInterp.Stats();
    const SSynthStats& made = mSynth.Stats();
    gpg::Logf(
      "server driver %s: view buffer %s, target %d beats (floor %d, most %d; raised %llu, lowered %llu), views late "
      "95%% %.0f ms, median %.0f ms; %llu late views, %llu underruns: %llu made up, %llu stalled (%.2f s, longest "
      "%.2f s), %llu caught up, %llu outages; made-up beats moved %llu entities, %llu eased back (%llu added), made-up "
      "positions %.3f off on average, %.3f at most (%llu compared)",
      when,
      !mInterp.Config().enabled ? "off" : (mInterp.Config().adaptive ? "adaptive" : "fixed"),
      static_cast<int>(mInterp.TargetDepth()),
      static_cast<int>(mInterp.Config().floorBeats),
      static_cast<int>(buffer.mostTarget),
      static_cast<unsigned long long>(buffer.raised),
      static_cast<unsigned long long>(buffer.lowered),
      buffer.lateness95Ms,
      buffer.latenessMedianMs,
      static_cast<unsigned long long>(buffer.lateViews),
      static_cast<unsigned long long>(buffer.underruns),
      static_cast<unsigned long long>(buffer.synthesized),
      static_cast<unsigned long long>(buffer.stalls),
      buffer.stallSeconds,
      buffer.longestStall,
      static_cast<unsigned long long>(buffer.catchUps),
      static_cast<unsigned long long>(buffer.outages),
      static_cast<unsigned long long>(made.moved),
      static_cast<unsigned long long>(made.eased),
      static_cast<unsigned long long>(made.easedAdded),
      made.compared != 0u ? made.errorSum / static_cast<double>(made.compared) : 0.0,
      made.errorMost,
      static_cast<unsigned long long>(made.compared)
    );
    if (mViews) {
      LogEffects(when, mViews->Effects().Total());
    }
  }

  void CNetworkSimDriver::ConfigureBuffer()
  {
    SInterpConfig config;
    config.enabled = net_ClientInterp != 0;
    config.adaptive = net_ClientInterpAdaptive != 0;
    config.floorBeats = net_ClientInterpTicks;
    config.maxBeats = net_ClientInterpMaxTicks;
    config.synthBeats = net_ClientExtrapolateBeats;
    if (mBufferConfigured && config == mBufferSwitches) {
      return;
    }
    mBufferConfigured = true;
    mBufferSwitches = config;
    mInterp.Configure(config);
    const SInterpConfig& used = mInterp.Config();
    gpg::Logf(
      "server driver: view buffer %s, %d to %d beats, up to %d made up",
      !used.enabled ? "off" : (used.adaptive ? "adaptive" : "fixed"),
      static_cast<int>(used.floorBeats),
      static_cast<int>(used.adaptive ? used.maxBeats : used.floorBeats),
      static_cast<int>(used.enabled ? used.synthBeats : 0)
    );
  }

  void CNetworkSimDriver::RecordBuffer(
    const double now
  ) const
  {
    const SInterpStats& stats = mInterp.Stats();
    SServerInterpSnapshot snapshot;
    snapshot.on = mInterp.Config().enabled;
    snapshot.adaptive = mInterp.Config().adaptive;
    snapshot.target = mInterp.TargetDepth();
    snapshot.depth = mInterp.Depth(now);
    snapshot.lateness95Ms = stats.lateness95Ms;
    snapshot.lateViews = stats.lateViews;
    snapshot.underruns = stats.underruns;
    snapshot.synthesized = stats.synthesized;
    snapshot.stalls = stats.stalls;
    snapshot.stallSeconds = stats.stallSeconds;
    snapshot.catchUps = stats.catchUps;
    CServerLaneMeter::Get().RecordInterp(snapshot);
  }

  void CNetworkSimDriver::StampView(
    const SViewMessage& view,
    moho::SSyncData& packet
  )
  {
    const double now = NowSeconds();
    ConfigureBuffer();
    mInterp.SetBeatSeconds(1.0 / mClock.ExpectedBeatsPerSecond());
    const wire::SViewFrame* const shown = mViews->Shown();
    // The server's clock when it built the beat; without a frame, where the beat would be at speed 0.
    const double serverSeconds =
      shown != nullptr ? static_cast<double>(shown->serverMs) / 1000.0 : static_cast<double>(view.beat) * 0.1;
    const SBeatStamp stamp = mInterp.OnView(static_cast<std::int32_t>(view.beat), serverSeconds, now);
    mFirstViewAt = mFirstViewAt < 0.0 ? now : mFirstViewAt;
    packet.mCurTick = stamp.tick;
    packet.mAdvanced = stamp.advanced;

    const CSyncRebuilder& rebuilder = mViews->Rebuilder();
    const CBeatSynthesizer::Lookup lookup = HeldLookup(rebuilder);
    mSynth.CompareWithReal(static_cast<std::int32_t>(view.beat), lookup);
    if (stamp.kind == EBeatKind::CatchUp) {
      mSynth.OnCatchUp(UpdatesOf(packet));
    } else if (mSynth.Shown() != 0u) {
      // The first beat with display time after made-up ones: each entity starts from where the screen showed it.
      std::vector<SSynthUpdate> updates = UpdatesOf(packet);
      std::vector<SSynthUpdate> added;
      mSynth.OnAdvance(updates, lookup, added);
      for (std::size_t i = 0; i < updates.size(); ++i) {
        FromSynth(updates[i].last, packet.mEntityUpdates[i].mVariableData.mLastTransform);
      }
      for (const SSynthUpdate& update : added) {
        CSyncRebuilder::SHeldView held;
        if (!rebuilder.FindHeld(update.id, false, held) || held.data == nullptr) {
          continue;
        }
        moho::SEntityVariableUpdateEntry& entry = packet.mEntityUpdates.emplace_back();
        entry.mEntityId = static_cast<moho::EntId>(update.id);
        entry.mVariableData = *held.data;
        FromSynth(update.last, entry.mVariableData.mLastTransform);
        FromSynth(update.cur, entry.mVariableData.mCurTransform);
      }
    }

    // What a made-up beat repeats of this one.
    mCarried->focusArmy = packet.mFocusArmy;
    mCarried->fogOfWar = packet.mFogOfWar;
    mCarried->pausedBy = packet.mPausedBy;
    mCarried->terrain.reset_from(packet.mTerrainUpdate);
    mCarried->resources.reset_from(packet.mSimResources);
    mStamps.push_back(stamp);

    if (const std::int32_t target = mInterp.TargetDepth(); target != mTargetLogged && mTargetChangesLogged < 20u) {
      ++mTargetChangesLogged;
      gpg::Logf(
        "server driver: view buffer target %d beats at beat %u (views late 95%% %.0f ms, median %.0f ms)",
        static_cast<int>(target),
        view.beat,
        mInterp.Stats().lateness95Ms,
        mInterp.Stats().latenessMedianMs
      );
      mTargetLogged = target;
    }
    RecordBuffer(now);
  }

  void CNetworkSimDriver::QueueSynthesized(
    const SBeatStamp& stamp
  )
  {
    auto packet = std::make_unique<moho::SSyncData>();
    packet->mCurBeat = stamp.beat;
    packet->mCurTick = stamp.tick;
    packet->mAdvanced = true;
    packet->mFocusArmy = mCarried->focusArmy;
    packet->mFogOfWar = mCarried->fogOfWar;
    packet->mPausedBy = mCarried->pausedBy;
    packet->mTerrainUpdate.reset_from(mCarried->terrain);
    if (mCarried->resources.px != nullptr) {
      packet->mSimResources.reset_from(mCarried->resources);
    } else {
      packet->mSimResources.reset_from_owner(mResources);
    }

    // Every moving entity carried on by its last beat's motion, from where the screen shows it; units whose pose moved
    // hold it. Nothing else changes: no creation, death, army, effect or Lua `Sync` is made up.
    const CSyncRebuilder& rebuilder = mViews->Rebuilder();
    const CBeatSynthesizer::Lookup lookup = HeldLookup(rebuilder);
    const CBeatSynthesizer::ForEach forEach = [&rebuilder](const auto& visit) {
      rebuilder.ForEachLive([&visit](const std::uint32_t id, const moho::SSTIEntityVariableData& data) {
        visit(id, ToSynth(data.mLastTransform), ToSynth(data.mCurTransform));
      });
    };
    std::vector<SSynthUpdate> updates;
    mSynth.Synthesize(stamp.tick, stamp.ahead, forEach, lookup, updates);
    packet->mEntityUpdates.reserve(updates.size());
    for (const SSynthUpdate& update : updates) {
      CSyncRebuilder::SHeldView held;
      if (!rebuilder.FindHeld(update.id, false, held) || held.data == nullptr) {
        continue;
      }
      moho::SEntityVariableUpdateEntry& entry = packet->mEntityUpdates.emplace_back();
      entry.mEntityId = static_cast<moho::EntId>(update.id);
      entry.mVariableData = *held.data;
      FromSynth(update.last, entry.mVariableData.mLastTransform);
      FromSynth(update.cur, entry.mVariableData.mCurTransform);
    }
    rebuilder.HeldPoseUpdates(packet->mUnitUpdates);

    auto* const stream = new gpg::MemBufferStream(static_cast<unsigned int>(mEmptySync.size() + 16u));
    stream->Write(reinterpret_cast<const char*>(mEmptySync.data()), mEmptySync.size());
    packet->mStream = stream;
    if (mInterp.Stats().synthesized <= 5u) {
      gpg::Logf(
        "server driver: beat made up at display tick %d, %d past view %d: %zu entities moved, %zu poses held",
        static_cast<int>(stamp.tick),
        static_cast<int>(stamp.ahead),
        static_cast<int>(stamp.beat),
        packet->mEntityUpdates.size(),
        packet->mUnitUpdates.size()
      );
    }
    mPackets.push_back(std::move(packet));
    mStamps.push_back(stamp);
    (void)::SetEvent(mAvailable);
  }

  void CNetworkSimDriver::LogEffects(
    const char* const when,
    const SEffectApplyCounts& counts
  ) const
  {
    // Plan WP9.3: the effects lane as this client applied it (`when`: a beat, or "so far" / "end" for every lane).
    const CEffectLaneApplier& effects = mViews->Effects();
    gpg::Logf(
      "server driver effects %s: %llu ops in %llu lanes (most %llu in one), %llu applied: %llu created (%llu replacing "
      "one held), %llu setters, %llu lights, %llu destroyed by script; dropped %llu with their entity, %llu at a whole "
      "view, %llu aged out; skipped %llu (entity not held %llu, unknown effect %llu, name not sent %llu, blueprint "
      "not held %llu); %llu lanes didn't decode; %zu held now",
      when,
      static_cast<unsigned long long>(counts.ops),
      static_cast<unsigned long long>(counts.lanes),
      static_cast<unsigned long long>(effects.MostOps()),
      static_cast<unsigned long long>(counts.applied),
      static_cast<unsigned long long>(counts.created),
      static_cast<unsigned long long>(counts.replaced),
      static_cast<unsigned long long>(counts.setters),
      static_cast<unsigned long long>(counts.lights),
      static_cast<unsigned long long>(counts.destroyedByScript),
      static_cast<unsigned long long>(counts.droppedWithEntity),
      static_cast<unsigned long long>(counts.droppedWhole),
      static_cast<unsigned long long>(counts.agedOut),
      static_cast<unsigned long long>(counts.Skipped()),
      static_cast<unsigned long long>(counts.skipped[static_cast<std::size_t>(EEffectSkip::EntityNotHeld)]),
      static_cast<unsigned long long>(counts.skipped[static_cast<std::size_t>(EEffectSkip::UnknownEffect)]),
      static_cast<unsigned long long>(counts.skipped[static_cast<std::size_t>(EEffectSkip::UnknownName)]),
      static_cast<unsigned long long>(counts.skipped[static_cast<std::size_t>(EEffectSkip::UnknownBlueprint)]),
      static_cast<unsigned long long>(counts.badLanes),
      effects.Live()
    );
    // Plan WP9.3: what the hosted effects drew, over the session (the per-beat lines carry the same totals so far).
    if (const CClientEffects* const hosted = mViews->Hosted(); hosted != nullptr) {
      const SHostedEffectCounts& drawn = hosted->Counts();
      gpg::Logf(
        "server driver hosted effects %s: %llu beats, %llu made (%llu not: blueprint or entity), %llu ended by "
        "themselves, %zu alive now (most %llu), %zu entities followed (most %llu); to the session: %llu particles, "
        "%llu trail segments, %llu beams, %llu lights; %zu cameras",
        when,
        static_cast<unsigned long long>(drawn.beats),
        static_cast<unsigned long long>(drawn.created),
        static_cast<unsigned long long>(drawn.createFailed),
        static_cast<unsigned long long>(drawn.endedByThemselves),
        hosted->Alive(),
        static_cast<unsigned long long>(drawn.mostAlive),
        hosted->Targets(),
        static_cast<unsigned long long>(drawn.mostTargets),
        static_cast<unsigned long long>(drawn.particles),
        static_cast<unsigned long long>(drawn.trails),
        static_cast<unsigned long long>(drawn.beams),
        static_cast<unsigned long long>(drawn.lights),
        hosted->Cameras().size()
      );
    }
  }

  void CNetworkSimDriver::SendChat(
    const int clientIndex,
    const gpg::MemBuffer<const char>& data
  )
  {
    const moho::IClient* const local = mClientManager.GetLocalClient();
    if (local != nullptr && local->GetIndex() == clientIndex) {
      // To itself (a line to everyone includes the sender): as a lockstep game's local client shows it.
      DeliverChat(
        clientIndex, std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(data.mBegin), data.Size())
      );
      return;
    }
    if (data.Size() > kMaxChatBytes) {
      ++mChatBad;
      return;
    }
    const std::vector<std::uint8_t> message = EncodeChatMessage(
      clientIndex, std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(data.mBegin), data.Size())
    );
    if (SendServerGameMessage(message)) {
      ++mChatSent;
    }
  }

  void CNetworkSimDriver::DeliverChat(
    const int senderIndex,
    const std::span<const std::uint8_t> payload
  )
  {
    const CRosterClient* const sender = mClientManager.RosterClient(senderIndex);
    if (sender == nullptr || mClientManager.mInterface == nullptr) {
      ++mChatBad;
      return;
    }
    ++mChatReceived;
    mClientManager.mInterface->ReceiveChat(sender, gpg::CopyMemBuffer(payload.data(), payload.size()));
  }

  void CNetworkSimDriver::Take(
    const std::vector<std::uint8_t>& message
  )
  {
    if (message.empty()) {
      return;
    }
    switch (static_cast<net::ESeatMessage>(message[0])) {
    case net::ESeatMessage::GameInfo: {
      SServerGameInfo info;
      if (!ReadGameInfo(message, info)) {
        gpg::Warnf("server driver: a malformed GameInfo");
        return;
      }
      // Again after a reconnect: the client keeps what it holds; the next view comes whole.
      if (!mViews) {
        mViews = std::make_unique<CServerViewClient>(mRules, info);
        // Plan WP9.3: the effects lane makes real effects, drawn from this session's cameras over its map.
        SEffectHostWorld world;
        world.cameras = [this](fa::vector<moho::GeomCamera3>& out) {
          const std::lock_guard<std::mutex> lock(mCameraLock);
          out = mCameras;
        };
        world.map = []() -> moho::STIMap* {
          moho::CWldSession* const session = moho::WLD_GetActiveSession();
          if (session == nullptr || session->mWldMap == nullptr || session->mWldMap->mTerrainRes == nullptr) {
            return nullptr;
          }
          return session->mWldMap->mTerrainRes->mMap;
        };
        mViews->HostEffects(mRules, std::move(world));
        if (mSeedHeights != nullptr) {
          mViews->SeedTerrain(
            *mSeedHeights
          ); // no edit has reached the session's field yet: none is applied before a view
        }
        gpg::Logf(
          "server driver: map %.0f x %.0f, army %d, source %u, %llu blueprints known",
          info.mapSizeX,
          info.mapSizeZ,
          static_cast<int>(info.army),
          info.source,
          static_cast<unsigned long long>(mViews->Stats().blueprintsKnown)
        );
      }
      return;
    }
    case net::ESeatMessage::View: {
      SViewMessage view;
      if (!mViews || !ReadViewMessage(message, view)) {
        ++mViewsBad;
        return;
      }
      SPendingView pending;
      pending.message = message;
      pending.beat = view.beat;
      if (const auto early = mEarlyLua.find(view.beat); early != mEarlyLua.end()) {
        pending.lua = std::move(early->second);
        pending.haveLua = true;
        mEarlyLua.erase(early);
      }
      mPendingViews.push_back(std::move(pending));
      ReleaseViews();
      return;
    }
    case net::ESeatMessage::LuaSync: {
      // Plan WP11: the beat's Lua lane, after the server routed the beat's `Sync`.
      net::ByteReader reader(message.data() + 1, message.size() - 1u);
      const auto beat = static_cast<std::uint32_t>(reader.Varint());
      const std::uint64_t size = reader.Varint();
      const std::uint8_t* const bytes = reader.Bytes(static_cast<std::size_t>(size));
      if (!reader.Ok()) {
        ++mLuaLanesBad;
        return;
      }
      std::vector<std::uint8_t> lane(bytes, bytes + size);
      const auto pending = std::find_if(mPendingViews.begin(), mPendingViews.end(), [beat](const SPendingView& view) {
        return view.beat == beat;
      });
      if (pending != mPendingViews.end()) {
        pending->lua = std::move(lane);
        pending->haveLua = true;
        ReleaseViews();
      } else if (mEarlyLua.size() < 64u) {
        mEarlyLua[beat] = std::move(lane);
      }
      return;
    }
    case net::ESeatMessage::SessionTables: {
      // Plan WP11 step 4: before the views that name its entries (or a reset, then every record again).
      STablesMessage tables;
      if (!mViews || !ReadTablesMessage(message, tables) || !mViews->ApplyTables(tables)) {
        ++mTablesBad;
      }
      return;
    }
    case net::ESeatMessage::Beat: {
      net::ByteReader reader(message.data() + 1, message.size() - 1u);
      const std::uint64_t beat = reader.Varint();
      if (reader.Ok()) {
        mServerBeat = static_cast<std::int32_t>(beat);
      }
      return;
    }
    case net::ESeatMessage::CommandAnswer: {
      // Plan WP3.7: the beat the command went in (or refused, or dropped), for each command in the order sent.
      net::ByteReader reader(message.data() + 1, message.size() - 1u);
      const auto beat = static_cast<std::int32_t>(reader.Varint());
      const std::uint8_t answer = reader.Byte();
      if (!reader.Ok() || answer > 2u) {
        return;
      }
      ++mAnswers[answer];
      if (mSentAtShown.empty()) {
        return;
      }
      const std::int32_t shownAtSending = mSentAtShown.front();
      mSentAtShown.pop_front();
      if (answer != 0u) {
        return; // refused or dropped: no beat
      }
      // #99: how far ahead of the beat shown at sending it went in; the issue beat follows the largest lately.
      const std::int32_t lead = beat - shownAtSending;
      mAnswersPastEstimate += lead > mIssueLead ? 1u : 0u;
      mLargestLead = std::max(mLargestLead, lead);
      mRecentLeads.push_back(lead);
      if (mRecentLeads.size() > kLeadWindow) {
        mRecentLeads.pop_front();
      }
      mIssueLead = std::max<std::int32_t>(1, *std::max_element(mRecentLeads.begin(), mRecentLeads.end()) + 1);
      return;
    }
    case net::ESeatMessage::Roster: {
      // Plan WP11.4: from now on the session's roster questions are answered from the server's.
      const std::optional<wire::SRoster> roster = DecodeRosterMessage(message);
      if (!roster) {
        ++mRostersBad;
        return;
      }
      ++mRosters;
      mClientManager.ApplyRoster(*roster, [this](const int index, const gpg::MemBuffer<const char> data) {
        SendChat(index, data);
      });
      if (mRosters == 1u) {
        gpg::Logf(
          "server driver: roster from the server, %zu clients, this one %d",
          roster->entries.size(),
          static_cast<int>(roster->localIndex)
        );
      }
      return;
    }
    case net::ESeatMessage::Chat: {
      int sender = 0;
      std::span<const std::uint8_t> payload;
      if (!DecodeChatMessage(message, sender, payload)) {
        ++mChatBad;
        return;
      }
      DeliverChat(sender, payload);
      return;
    }
    case net::ESeatMessage::FocusArmy: {
      // Plan WP11.1: the army the server grants; the client shows it from the next view on.
      if (const std::optional<int> granted = DecodeFocusArmy(message); granted) {
        mFocusGranted.store(*granted, std::memory_order_relaxed);
        gpg::Logf("server driver: the server grants focus on army %d", *granted);
      }
      return;
    }
    default:
      return; // LaunchInfo (the session was made from it), ViewCheck (the probe compares; not yet here)
    }
  }

  void CNetworkSimDriver::ReleaseViews()
  {
    // In order: a view waits for its beat's `LuaSync`, unless the next beat's view is here (none is coming then).
    while (!mPendingViews.empty() && (mPendingViews.front().haveLua || mPendingViews.size() > 1u)) {
      SPendingView pending = std::move(mPendingViews.front());
      mPendingViews.pop_front();
      SViewMessage view;
      if (!ReadViewMessage(pending.message, view)) {
        ++mViewsBad;
        continue;
      }
      if (!pending.haveLua) {
        ++mLuaMissing;
      }
      QueueView(view, pending.haveLua ? std::span<const std::uint8_t>(pending.lua) : view.lua);
    }
  }

  void CNetworkSimDriver::QueueView(
    const SViewMessage& view,
    const std::span<const std::uint8_t> lua
  )
  {
    ++mViewsTaken;
    // Plan WP10.10: this view's bytes by lane, for the network panel and the summary.
    std::array<std::uint64_t, kServerLaneCount> laneBytes{};
    laneBytes[static_cast<std::size_t>(EServerLane::Entities)] = view.own.size() + view.team.size();
    laneBytes[static_cast<std::size_t>(EServerLane::Armies)] = view.armies.size();
    laneBytes[static_cast<std::size_t>(EServerLane::Grids)] = view.grids.size();
    laneBytes[static_cast<std::size_t>(EServerLane::Lua)] = lua.size();
    laneBytes[static_cast<std::size_t>(EServerLane::Poses)] = view.hasPoses ? view.poses.size() : 0u;
    laneBytes[static_cast<std::size_t>(EServerLane::Effects)] = view.effects.size();
    if (mViewsTaken == 1u) {
      CServerLaneMeter::Get().Reset(); // a new game
    }
    CServerLaneMeter::Get().Record(laneBytes);
    static_assert(std::tuple_size_v<decltype(mLaneBytes)> == kServerLaneCount, "a total per lane");
    for (std::size_t lane = 0; lane < kServerLaneCount; ++lane) {
      mLaneBytes[lane] += laneBytes[lane];
    }
    auto packet = std::make_unique<moho::SSyncData>();
    packet->mCurBeat = static_cast<std::int32_t>(view.beat);
    packet->mCurTick = static_cast<std::int32_t>(view.beat);
    packet->mAdvanced = true;
    packet->mFocusArmy = mFocusGranted.load(std::memory_order_relaxed) == kNoFocusGranted
      ? mViews->Info().army
      : mFocusGranted.load(std::memory_order_relaxed);
    if (!mArmiesGiven) {
      mArmiesGiven = true;
      for (const moho::SSTIArmyConstantData& army : mArmyConstants) {
        packet->mNewGrids.push_back(army);
      }
    }
    const auto applyStart = std::chrono::steady_clock::now();
    if (!mViews->Apply(view, *packet)) {
      ++mViewsBad;
      return;
    }
    // Plan WP9.3: the beat's effects lane, applied with the view: its counts for the panel, and for the log the first
    // beats with ops and the first that skipped any.
    {
      const CEffectLaneApplier& effects = mViews->Effects();
      const SEffectApplyCounts& beat = effects.LastLane();
      CServerLaneMeter::Get().RecordEffects(effects.Live(), effects.Total().applied, effects.Total().Skipped());
      const bool first = beat.ops != 0u && mEffectLanesLogged < 3u;
      const bool skipped = beat.Skipped() != 0u && mEffectSkipsLogged < 10u;
      if (first || skipped) {
        mEffectLanesLogged += first ? 1u : 0u;
        mEffectSkipsLogged += skipped ? 1u : 0u;
        char when[32];
        std::snprintf(when, sizeof(when), "beat %u", view.beat);
        LogEffects(when, beat);
      }
    }
    // Plan WP10.7: what applying a view costs this machine is its share of a beat, as a lockstep client's sim beat is;
    // the speed step it allows goes to the server whenever it changes (lockstep's `CLIMSG_IntParam`).
    mSpeedMeter.Add(std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - applyStart).count());
    if (const std::optional<int> limit = mSpeedMeter.Settled(); limit) {
      const bool sent = SendServerGameMessage(EncodeSpeedLimit(*limit));
      gpg::Logf(
        "server driver: this game keeps up with speed %+d%s", *limit, sent ? "" : " (not sent: no server link)"
      );
    }
    // #178: the frame's header carries the server's sim rate and clock; the session paces by them.
    if (const wire::SViewFrame* const shown = mViews->Shown(); shown != nullptr) {
      const double now = std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
      mClock.OnFrame(view.beat, shown->simRate, shown->serverMs, now);
      mClientManager.SetServerSimRate(shown->simRate);
    }
    if (packet->mSimResources.px == nullptr) {
      packet->mSimResources.reset_from_owner(mResources);
    }
    // Every army's record as this client holds it.
    const std::vector<wire::SArmyRecord>& armies = mViews->Armies();
    packet->mArmyUpdates.resize(armies.size());
    for (std::size_t index = 0; index < armies.size(); ++index) {
      ArmyFromWire(armies[index], packet->mArmyUpdates[index], &mRules);
    }
    // The beat's Lua `Sync` table (the session deserialises it every beat): the view's Lua lane, or an empty table.
    std::vector<std::uint8_t> table;
    std::vector<std::string> prints;
    if (!lua.empty()) {
      wire::BitReader reader(lua);
      if (!wire::DecodeLuaSyncLane(reader, table, prints)) {
        ++mLuaLanesBad;
        table.clear();
      }
    }
    const std::vector<std::uint8_t>& sync = table.empty() ? mEmptySync : table;
    if (mViewsTaken <= 3u || (!table.empty() && mLuaTablesLogged < 3u)) {
      // The first beats' Lua `Sync` (what the session's `OnSync` gets), for the log.
      static constexpr char kPlayableArea[] = "NewPlayableArea";
      const bool playableArea =
        std::search(table.begin(), table.end(), std::begin(kPlayableArea), std::end(kPlayableArea) - 1) != table.end();
      mLuaTablesLogged += table.empty() ? 0u : 1u;
      gpg::Logf(
        "server driver: beat %u Lua lane %zu bytes, Sync table %zu bytes%s, %zu prints",
        view.beat,
        lua.size(),
        table.size(),
        playableArea ? " (NewPlayableArea)" : "",
        prints.size()
      );
    }
    auto* const stream = new gpg::MemBufferStream(static_cast<unsigned int>(sync.size() + 16u));
    stream->Write(reinterpret_cast<const char*>(sync.data()), sync.size());
    packet->mStream = stream;
    StampView(view, *packet); // plan WP10.9: its display tick, with its stamp queued beside it
    mLastBeat = packet->mCurBeat;
    mPackets.push_back(std::move(packet));
    (void)::SetEvent(mAvailable);
    if (mViewsTaken % kSummaryEveryViews == 0u) {
      LogSummary("so far");
    }
  }

  void CNetworkSimDriver::SendCommandFrame(
    moho::CMessage& message
  )
  {
    // As the probe sends one: the kind, then the whole message (type, 16-bit size, payload).
    std::vector<std::uint8_t> frame;
    frame.reserve(1u + message.mBuff.Size());
    frame.push_back(static_cast<std::uint8_t>(net::ESeatMessage::Command));
    const auto* const bytes = reinterpret_cast<const std::uint8_t*>(message.mBuff.start_);
    frame.insert(frame.end(), bytes, bytes + message.mBuff.Size());
    if (SendServerGameMessage(frame)) {
      ++mCommandsSent;
      mSentAtShown.push_back(mLastBeat < 0 ? 0 : mLastBeat); // answered in this order (CommandAnswer)
    }
  }

  moho::CmdId CNetworkSimDriver::IssueBeat() const noexcept
  {
    // #99: the beat the server is likely to apply it in, as the last answers measured it from the beat shown.
    return static_cast<moho::CmdId>((mLastBeat < 0 ? 0 : mLastBeat) + mIssueLead);
  }

  void CNetworkSimDriver::DisconnectClients() {}

  void CNetworkSimDriver::ShutDown()
  {
    if (!std::exchange(mShutDown, true)) {
      const std::uint8_t leaving = static_cast<std::uint8_t>(net::ESeatMessage::Leaving);
      (void)SendServerGameMessage(std::span<const std::uint8_t>(&leaving, 1u));
    }
  }

  moho::CClientManagerImpl* CNetworkSimDriver::GetClientManager()
  {
    return &mClientManager;
  }

  void CNetworkSimDriver::NoOp() {}

  void CNetworkSimDriver::Dispatch()
  {
    std::vector<std::uint8_t> message;
    while (TakeServerGameMessage(message)) {
      Take(message);
    }
  }

  void CNetworkSimDriver::IncrementOutstandingRequests() {}

  void CNetworkSimDriver::DecrementOutstandingRequestsAndSignal() {}

  bool CNetworkSimDriver::HasSyncData()
  {
    // Plan WP10.9: the session asks when its clock reached its next tick (`CWldSession::SessionFrame`).
    if (!mPackets.empty()) {
      // The game's start: the first beat waits until the buffer holds its depth (a second at the most).
      constexpr double kMostStartHold = 1.0;
      return mRealTaken != 0u || !mInterp.HoldStart() || NowSeconds() - mFirstViewAt >= kMostStartHold;
    }
    if (mRealTaken == 0u || mShutDown || !mViews) {
      return false;
    }
    // None has come for that tick: the buffer may let one be made up, or the picture waits.
    ConfigureBuffer();
    const double now = NowSeconds();
    const std::optional<SBeatStamp> stamp = mInterp.OnUnderrun(now);
    if (!stamp) {
      RecordBuffer(now);
      return false;
    }
    QueueSynthesized(*stamp);
    return true;
  }

  void CNetworkSimDriver::GetSyncData(
    moho::SSyncData*& outSyncData
  )
  {
    // Never blocks: the session asks only after `HasSyncData`.
    outSyncData = nullptr;
    if (!mPackets.empty()) {
      outSyncData = mPackets.front().release();
      mPackets.pop_front();
      if (!mStamps.empty()) {
        const SBeatStamp stamp = mStamps.front();
        mStamps.pop_front();
        const double now = NowSeconds();
        mInterp.OnTaken(stamp, now);
        mRealTaken += stamp.kind != EBeatKind::Synthesized ? 1u : 0u;
        RecordBuffer(now);
      }
      mClock.OnShown(static_cast<std::uint32_t>(outSyncData->mCurBeat));
    }
    if (mPackets.empty()) {
      (void)::ResetEvent(mAvailable);
    }
  }

  HANDLE CNetworkSimDriver::GetSyncDataAvailableEvent()
  {
    return mAvailable;
  }

  double CNetworkSimDriver::GetSimSpeed()
  {
    // #178, plan WP10.9: `WLD_GetSimRate`'s skew, so the display keeps the view buffer's depth behind the server's
    // beats.
    return mInterp.HasViews() ? mInterp.Skew(NowSeconds()) : 0.0;
  }

  void CNetworkSimDriver::SetArmyIndex(
    const int army
  )
  {
    // Plan WP11.1: a request; the server answers with the army it grants (`FocusArmy`), which the views then carry.
    const int shown = mFocusGranted.load(std::memory_order_relaxed);
    if (army == shown || (shown == kNoFocusGranted && mViews && army == mViews->Info().army)) {
      return;
    }
    const bool sent = SendServerGameMessage(EncodeFocusArmy(army));
    gpg::Logf("server driver: focus on army %d asked of the server%s", army, sent ? "" : " (not sent: no server link)");
  }

  void CNetworkSimDriver::SetGeomCams(
    const fa::vector<moho::GeomCamera3>& cameras
  )
  {
    // Plan WP9.3: the hosted effects see what the session's cameras see, as a lockstep sim's effects see the cameras
    // this call gives its sync filter.
    {
      const std::lock_guard<std::mutex> lock(mCameraLock);
      mCameras = cameras;
    }
    // Plan WP11.1: what the cameras see goes to the server at most every kCameraPeriodMs (for WP8.2's camera order).
    const auto now = std::chrono::steady_clock::now();
    if (now - mCamerasSentAt < std::chrono::milliseconds(kCameraPeriodMs)) {
      return;
    }
    std::vector<SCameraReport> reports;
    for (const moho::GeomCamera3& camera : cameras) {
      if (reports.size() == kMaxCameras) {
        break;
      }
      static_assert(sizeof(camera.viewProjection) == sizeof(float) * 16, "a 4x4 float matrix");
      SCameraReport report;
      std::memcpy(report.viewProjection.data(), &camera.viewProjection, sizeof(float) * 16);
      report.lodScale = camera.lodScale;
      reports.push_back(report);
    }
    if (SendServerGameMessage(EncodeCameras(reports))) {
      mCamerasSentAt = now;
      ++mCamerasSent;
    }
  }

  // The sync filters choose what a local sim passes to the UI; a server game's views are the server's (plan WP4), so
  // nothing here changes what it sends.
  void CNetworkSimDriver::SetSyncFilterMaskA(
    const moho::SSyncFilterMaskBlock&
  )
  {}
  void CNetworkSimDriver::SetSyncFilterMaskB(
    const moho::SSyncFilterMaskBlock&
  )
  {}
  void CNetworkSimDriver::SetSyncFilterOptionFlag(
    const bool
  )
  {}

  void CNetworkSimDriver::RequestPause(
    std::int32_t* const outCommandCookie
  )
  {
    mMarshaller.RequestPause();
    if (outCommandCookie != nullptr) {
      *outCommandCookie = static_cast<std::int32_t>(IssueBeat());
    }
  }

  void CNetworkSimDriver::Resume(
    std::int32_t* const outCommandCookie
  )
  {
    mMarshaller.Resume();
    if (outCommandCookie != nullptr) {
      *outCommandCookie = static_cast<std::int32_t>(IssueBeat());
    }
  }

  // Commands as a lockstep client sends them; the server refuses those a player may not give (single step, creating,
  // destroying and warping entities, Lua in the sim, debug commands: remote/ServerClient.cpp).
  moho::CmdId CNetworkSimDriver::SingleStep()
  {
    mMarshaller.SingleStep();
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::CreateUnit(
    const uint32_t armyIndex,
    const moho::RResId& id,
    const moho::SCoordsVec2& pos,
    const float heading
  )
  {
    mMarshaller.CreateUnit(armyIndex, id, pos, heading);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::CreateProp(
    const char* const id,
    const Wm3::Vec3f& loc
  )
  {
    mMarshaller.CreateProp(id, loc);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::DestroyEntity(
    const moho::EntId entityId
  )
  {
    mMarshaller.DestroyEntity(entityId);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::WarpEntity(
    const moho::EntId entityId,
    const moho::VTransform& transform
  )
  {
    mMarshaller.WarpEntity(entityId, transform);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::ProcessInfoPair(
    const moho::EntId entityId,
    const gpg::StrArg key,
    const gpg::StrArg val
  )
  {
    mMarshaller.ProcessInfoPair(entityId, key, val);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::IssueCommand(
    const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities,
    const moho::SSTICommandIssueData& data,
    const bool clear
  )
  {
    mMarshaller.IssueCommand(entities, data, clear);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::IssueFactoryCommand(
    const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities,
    const moho::SSTICommandIssueData& data,
    const bool clear
  )
  {
    mMarshaller.IssueFactoryCommand(entities, data, clear);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::IncreaseCommandCount(
    const moho::CmdId id,
    const int count
  )
  {
    mMarshaller.IncreaseCommandCount(id, count);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::DecreaseCommandCount(
    const moho::CmdId id,
    const int count
  )
  {
    mMarshaller.DecreaseCommandCount(id, count);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::SetCommandTarget(
    const moho::CmdId id,
    const moho::SSTITarget& target
  )
  {
    mMarshaller.SetCommandTarget(id, target);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::SetCommandType(
    const moho::CmdId id,
    const moho::EUnitCommandType type
  )
  {
    mMarshaller.SetCommandType(id, type);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::SetCommandCells(
    const moho::CmdId id,
    const gpg::core::FastVector<moho::SOCellPos>& cells,
    const Wm3::Vector3<float>& target
  )
  {
    mMarshaller.SetCommandCells(id, cells, target);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::RemoveCommandFromUnitQueue(
    const moho::CmdId id,
    const moho::EntId unitId
  )
  {
    mMarshaller.RemoveCommandFromUnitQueue(id, unitId);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::ExecuteLuaInSim(
    const char* const lua,
    const LuaPlus::LuaObject& args
  )
  {
    mMarshaller.ExecuteLuaInSim(lua, args);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::LuaSimCallback(
    const char* const fnName,
    const LuaPlus::LuaObject& args,
    const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities
  )
  {
    mMarshaller.LuaSimCallback(fnName, args, entities);
    return IssueBeat();
  }

  moho::CmdId CNetworkSimDriver::ExecuteDebugCommand(
    const char* const command,
    const Wm3::Vector3<float>& worldPos,
    const uint32_t focusArmy,
    const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities
  )
  {
    mMarshaller.ExecuteDebugCommand(command, worldPos, focusArmy, entities);
    return IssueBeat();
  }

  moho::Sim* CNetworkSimDriver::ProcessEvents()
  {
    return nullptr;
  }

  void CNetworkSimDriver::ReleaseInterlockRef() {}

  void CNetworkSimDriver::RequestSaveGame(
    moho::ISaveRequest* const request
  )
  {
    // A client with no sim has nothing to save; the server keeps the game (and its replay).
    (void)request;
    gpg::Warnf("server driver: a save was asked for; a server game can't be saved by a player");
  }

  void CNetworkSimDriver::DrawNetworkStats(
    moho::CD3DPrimBatcher*,
    float,
    float,
    float,
    float
  )
  {}

  namespace
  {
    SServerLaunch sLaunch;
    bool sHaveLaunch = false;
  } // namespace

  void SetServerLaunch(
    const SServerLaunch& launch
  )
  {
    sLaunch = launch;
    sHaveLaunch = true;
  }

  bool HasServerLaunch() noexcept
  {
    return sHaveLaunch;
  }

  moho::ISTIDriver* CreateServerSessionDriver(
    moho::RRuleGameRules& rules,
    const moho::LaunchInfoBase& launch,
    const moho::CHeightField* const heights
  )
  {
    return new CNetworkSimDriver(
      rules, launch, sLaunch.playerName.c_str(), sLaunch.clientIndex, sLaunch.uid, sLaunch.source, heights
    );
  }
} // namespace faf::remote::client
