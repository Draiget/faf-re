#include "remote/client/LoopbackLink.h"

#include <algorithm>
#include <chrono>
#include <utility>

#include "gpg/core/containers/String.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SimDriver.h"
#include "remote/ContentTables.h"
#include "remote/wire/WireVersion.h"
#include "moho/net/CClientBase.h"

// Engine addition, server mode: see LoopbackLink.h.

namespace faf::remote::client
{
  wire::SFrameCodec MakeLoopbackCodec(const float mapSizeX, const float mapSizeZ, const SLoopbackOptions& options)
  {
    wire::SFrameCodec codec{};
    codec.position = wire::SPositionQuantizer::ForMap(mapSizeX, mapSizeZ);
    codec.maxEntities = 1u << 20;
    codec.deadReckoning = options.deadReckoningTolerance != 0u;
    codec.velocityFractionBits = codec.deadReckoning ? options.velocityFractionBits : 0u;
    codec.orientationReckoning = codec.deadReckoning && options.orientationTolerance != 0u;
    return codec;
  }

  CLoopbackLink::CLoopbackLink(
    moho::RRuleGameRules& rules, const wire::SFrameCodec& codec, const SLoopbackOptions& options
  )
    : mTables(BuildContentTables(rules))
    , mClientContent(BuildContentTables(rules))
    , mCodec(codec)
    , mBuilder(mTables, codec)
    , mRebuilder(codec, ResolveBlueprints(rules, mClientContent), ResolveMeshes(rules, mClientContent))
  {
    // Connect (WP7.2): the server says hello with its protocol, lane versions and content hash;
    // the client compares them with its own and refuses to play on a mismatch.
    wire::SWireHello serverHello{};
    serverHello.contentHash = mTables.Hash();
    wire::BitWriter helloWriter;
    serverHello.Encode(helloWriter);
    wire::BitReader helloReader(helloWriter.Bytes());
    const std::optional<wire::SWireHello> received = wire::SWireHello::Decode(helloReader);
    wire::SWireHello clientHello{};
    clientHello.contentHash = mClientContent.Hash();
    if (!received) {
      mRefusal = "malformed hello";
    } else if (const std::optional<std::string> why = wire::WireIncompatibility(clientHello, *received); why) {
      mRefusal = *why;
    }
    if (options.deadReckoningTolerance != 0u && mCodec.deadReckoning) {
      wire::SReckoningScheme scheme{};
      scheme.tolerance = options.deadReckoningTolerance;
      scheme.window = options.reckoningWindow;
      scheme.verticalAcceleration = options.reckonVerticalAcceleration;
      scheme.orientationTolerance = options.orientationTolerance;
      mReckoner.emplace(scheme);
    }
    mBuilder.SetSessionTables(&mServerTables);
    mRebuilder.SetSessionTables(&mClientTables);
    mRebuilder.SetRules(&rules);
  }

  void CLoopbackLink::Pass(moho::SSyncData& packet)
  {
    if (!mRefusal.empty()) {
      return; // refused at connect: the packet stays the sim's own
    }
    // Server: the frame of this beat, against the frame sent last (in loopback every frame
    // arrives, so the last one sent is always acknowledged).
    using Clock = std::chrono::steady_clock;
    const Clock::time_point start = Clock::now();
    mBuilder.Apply(packet);
    if (const moho::CHeightField* const sent = mBuilder.SentTerrain(); sent != nullptr) {
      mRebuilder.SeedTerrain(*sent); // both ends start from one snapshot of the heights
    }
    wire::SViewFrame frame = mBuilder.Build(static_cast<std::uint32_t>(packet.mCurBeat));
    frame.simRate = mServerSimRate;
    frame.serverMs = static_cast<std::uint32_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - mStart).count()
    );
    if (mReckoner) {
      mReckoner->Apply(frame, mCodec);
    }
    wire::BitWriter writer;
    if (!wire::EncodeFrame(frame, mHasSent ? &mLastSent : nullptr, mCodec, writer)) {
      // Nothing usable to send: the client keeps the packet as the sim made it this beat.
      ++mEncodeFailures;
      return;
    }
    mLastSent = std::move(frame);
    mHasSent = true;
    // The session-table entries this beat's frame names go first (the reliable stream).
    if (mServerTables.HasPending()) {
      wire::BitWriter tables;
      mServerTables.WritePending(tables);
      mTableBytes += tables.Bytes().size();
      wire::BitReader reader(tables.Bytes());
      if (!mClientTables.Read(reader)) {
        ++mTableFailures;
      }
    }
    const Clock::time_point encoded = Clock::now();

    // Client.
    if (!mRebuilder.Apply(writer.Bytes(), packet)) {
      ++mRebuildFailures;
    } else if (const wire::SViewFrame* const shown = mRebuilder.Baseline(); shown != nullptr) {
      const double now = std::chrono::duration<double>(Clock::now() - mStart).count();
      mClock.OnFrame(shown->beat, shown->simRate, shown->serverMs, now);
      mClock.OnShown(shown->beat); // loopback: the session takes this packet now
    }
    const Clock::time_point rebuilt = Clock::now();
    mServerSeconds += std::chrono::duration<double>(encoded - start).count();
    mClientSeconds += std::chrono::duration<double>(rebuilt - encoded).count();
    mMaxBeatSeconds = std::max(mMaxBeatSeconds, std::chrono::duration<double>(rebuilt - start).count());
  }

  void CLoopbackLink::PassRoster(moho::IClientManager& standIn, CRemoteClientManager& facade)
  {
    if (!mRefusal.empty()) {
      return;
    }
    const moho::IClient* const local = standIn.GetLocalClient();
    const wire::SRoster roster = ReadRoster(standIn, local != nullptr ? local->GetIndex() : -1);
    ++mRosterBeat;
    if (mHaveSentRoster && roster == mSentRoster) {
      return;
    }
    // Who is there, their names, sources and votes go at once; ping and quiet time once a second.
    const auto withoutTimes = [](wire::SRoster r) {
      for (wire::SRosterEntry& entry : r.entries) {
        entry.ping = 0.0f;
        entry.quiet = 0.0f;
      }
      return r;
    };
    if (mHaveSentRoster && withoutTimes(roster) == withoutTimes(mSentRoster) && mRosterBeat < 10u) {
      return;
    }
    wire::BitWriter writer;
    roster.Encode(writer);
    mRosterBytes += writer.Bytes().size();
    ++mRostersSent;
    wire::BitReader reader(writer.Bytes());
    const std::optional<wire::SRoster> received = wire::SRoster::Decode(reader);
    if (!received || !(*received == roster)) {
      ++mRosterFailures;
      return;
    }
    facade.ApplyRoster(*received, [&standIn](const int clientIndex, const gpg::MemBuffer<const char> data) {
      // The server relays a client's chat to its addressee.
      if (moho::IClient* const target = standIn.GetClient(clientIndex); target != nullptr) {
        target->ReceiveChat(data);
      }
    });
    mSentRoster = roster;
    mHaveSentRoster = true;
    mRosterBeat = 0;

    // Check: the facade answers the roster questions as the stand-in does.
    bool same = facade.NumberOfClients() == standIn.NumberOfClients()
             && (facade.GetLocalClient() == nullptr) == (standIn.GetLocalClient() == nullptr);
    for (std::size_t i = 0; same && i < standIn.NumberOfClients(); ++i) {
      auto* const a = static_cast<moho::CClientBase*>(standIn.GetClient(static_cast<int>(i)));
      auto* const b = static_cast<moho::CClientBase*>(facade.GetClient(static_cast<int>(i)));
      same = (a == nullptr) == (b == nullptr);
      if (same && a != nullptr) {
        same = a->GetNickname().view() == b->GetNickname().view() && a->GetOwnerId() == b->GetOwnerId()
            && a->mSimRate == b->mSimRate && a->NoEjectionPending() == b->NoEjectionPending()
            && (a == standIn.GetLocalClient()) == (b == facade.GetLocalClient());
        const moho::BVIntSet* const sa = a->GetValidCommandSources();
        const moho::BVIntSet* const sb = b->GetValidCommandSources();
        for (unsigned int va = sa->GetNext(~0u), vb = sb->GetNext(~0u); same; va = sa->GetNext(va), vb = sb->GetNext(vb)) {
          same = (va == sa->Max()) == (vb == sb->Max()) && (va == sa->Max() || va == vb);
          if (va == sa->Max()) {
            break;
          }
        }
      }
    }
    mRosterMismatches += same ? 0u : 1u;
  }

  std::uint64_t CLoopbackLink::CheckFailures() const noexcept
  {
    const SRebuildStats& s = mRebuilder.Stats();
    return (mRefusal.empty() ? 0u : 1u) + mEncodeFailures + mRebuildFailures + mTableFailures + s.decodeFailures + s.soundMismatches
         + s.underlayMismatches + s.unknownTableIds + mBuilder.UnknownUnderlays() + s.createdNotInPacket + s.packetCreatedNotRebuilt
         + s.blueprintMismatches + s.eraseMismatches + s.deleteMismatches + s.packetUpdatesDropped
         + s.unitChangesWithoutUpdate + s.unitConstantsMissing + s.meshMismatches + s.meshResourceMismatches
         + s.positionsOutOfRange + s.tickMismatches + s.unitDataMismatches + s.depositMismatches
         + mBuilder.DepositOverflows() + s.terrainRectMismatches + mRebuilder.TerrainCellsDiffering()
         + mBuilder.TerrainEditOverflows() + mRosterFailures + mRosterMismatches;
  }

  std::string CLoopbackLink::Summary(const char* const when) const
  {
    const SRebuildStats& s = mRebuilder.Stats();
    const double frames = s.frames != 0u ? static_cast<double>(s.frames) : 1.0;
    const auto u = [](const std::uint64_t value) { return static_cast<unsigned long long>(value); };
    std::string text = mRefusal.empty() ? std::string() : "loopback REFUSED at connect: " + mRefusal + "; ";
    text += gpg::STR_Printf(
      "loopback %s: frames %llu, %.1f KB/s, encode failures %llu, decode failures %llu, rebuild failures %llu, "
      "created %llu, erased %llu, deleted %llu, entity updates %llu (settle %llu, packet data %llu), "
      "max position error %.5f, max orientation error %.3f deg, time per beat %.2f ms server + %.2f ms client (decode %.2f, delta %.2f, rebuild "
      "%.2f; max %.1f ms)",
      when, u(s.frames), static_cast<double>(s.frameBytes) / frames * 10.0 / 1024.0, u(mEncodeFailures),
      u(s.decodeFailures), u(mRebuildFailures), u(s.created), u(s.erased), u(s.deleted), u(s.entityUpdates),
      u(s.settleUpdates), u(s.entityDataBorrowed), s.maxPositionError, s.maxOrientationError, mServerSeconds * 1000.0 / frames,
      mClientSeconds * 1000.0 / frames, s.decodeSeconds * 1000.0 / frames, s.deltaSeconds * 1000.0 / frames,
      s.rebuildSeconds * 1000.0 / frames, mMaxBeatSeconds * 1000.0
    ).c_str();
    text += "\n";
    text += gpg::STR_Printf(
      "loopback %s checks: created not in packet %llu, packet creations not rebuilt %llu, blueprint mismatches %llu, "
      "creations without blueprint %llu, erase mismatches %llu, delete mismatches %llu, packet updates dropped %llu, "
      "unit changes without update %llu, unit constants differing %llu, mesh mismatches %llu, mesh resource "
      "mismatches %llu, positions out of range %llu, sound mismatches %llu, underlay mismatches %llu, unknown "
      "underlays %llu, unknown table ids %llu, table failures %llu (table records %.2f KB in all), creation tick "
      "mismatches %llu, unit stat items applied %llu, unit updates %llu (with the packet's poses %llu), unit data "
      "mismatches %llu, resource deposits %zu (mismatches %llu, overflows %llu), terrain edits %llu (rectangle "
      "mismatches %llu, height cells differing from the sim's now %llu, overflows %llu), rosters %llu (%.2f KB, "
      "failures %llu, mismatches %llu); clock: sim rate %d, beats/s expected %.2f, on the server's clock %.2f, "
      "arriving %.2f, backlog %lld, skew %.2f",
      when, u(s.createdNotInPacket), u(s.packetCreatedNotRebuilt), u(s.blueprintMismatches), u(s.noBlueprint),
      u(s.eraseMismatches), u(s.deleteMismatches), u(s.packetUpdatesDropped), u(s.unitChangesWithoutUpdate),
      u(s.unitConstantsMissing), u(s.meshMismatches), u(s.meshResourceMismatches), u(s.positionsOutOfRange),
      u(s.soundMismatches), u(s.underlayMismatches), u(mBuilder.UnknownUnderlays()), u(s.unknownTableIds),
      u(mTableFailures), static_cast<double>(mTableBytes) / 1024.0, u(s.tickMismatches), u(s.statsApplied),
      u(s.unitUpdates), u(s.unitPosesBorrowed), u(s.unitDataMismatches), mClientTables.Deposits().size(),
      u(s.depositMismatches), u(mBuilder.DepositOverflows()), u(s.terrainEdits), u(s.terrainRectMismatches),
      u(mRebuilder.TerrainCellsDiffering()), u(mBuilder.TerrainEditOverflows()), u(mRostersSent),
      static_cast<double>(mRosterBytes) / 1024.0, u(mRosterFailures), u(mRosterMismatches), mClock.ServerSimRate(),
      mClock.ExpectedBeatsPerSecond(), mClock.ServerBeatsPerSecond(), mClock.ArrivalBeatsPerSecond(),
      static_cast<long long>(mClock.Backlog()), mClock.Skew()
    ).c_str();
    return text;
  }
} // namespace faf::remote::client
