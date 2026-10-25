#include "remote/client/LoopbackLink.h"

#include <algorithm>
#include <chrono>
#include <utility>

#include "gpg/core/containers/String.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SimDriver.h"
#include "remote/ContentTables.h"

// Engine addition, server mode: see LoopbackLink.h.

namespace faf::remote::client
{
  wire::SFrameCodec MakeLoopbackCodec(const float mapSizeX, const float mapSizeZ, const SLoopbackOptions& options)
  {
    wire::SFrameCodec codec{};
    codec.position = wire::SPositionQuantizer::ForMap(mapSizeX, mapSizeZ);
    codec.maxEntities = 1u << 20;
    codec.deadReckoning = options.deadReckoningTolerance != 0u;
    return codec;
  }

  CLoopbackLink::CLoopbackLink(
    moho::RRuleGameRules& rules, const wire::SFrameCodec& codec, const SLoopbackOptions& options
  )
    : mTables(BuildContentTables(rules))
    , mCodec(codec)
    , mBuilder(mTables, codec)
    , mRebuilder(codec, ResolveBlueprints(rules, mTables), ResolveMeshes(rules, mTables))
  {
    if (options.deadReckoningTolerance != 0u && mCodec.deadReckoning) {
      mReckoner.emplace(options.deadReckoningTolerance);
    }
    mBuilder.SetSessionTables(&mServerTables);
    mRebuilder.SetSessionTables(&mClientTables);
  }

  void CLoopbackLink::Pass(moho::SSyncData& packet)
  {
    // Server: the frame of this beat, against the frame sent last (in loopback every frame
    // arrives, so the last one sent is always acknowledged).
    using Clock = std::chrono::steady_clock;
    const Clock::time_point start = Clock::now();
    mBuilder.Apply(packet);
    wire::SViewFrame frame = mBuilder.Build(static_cast<std::uint32_t>(packet.mCurBeat));
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
    }
    const Clock::time_point rebuilt = Clock::now();
    mServerSeconds += std::chrono::duration<double>(encoded - start).count();
    mClientSeconds += std::chrono::duration<double>(rebuilt - encoded).count();
    mMaxBeatSeconds = std::max(mMaxBeatSeconds, std::chrono::duration<double>(rebuilt - start).count());
  }

  std::uint64_t CLoopbackLink::CheckFailures() const noexcept
  {
    const SRebuildStats& s = mRebuilder.Stats();
    return mEncodeFailures + mRebuildFailures + mTableFailures + s.decodeFailures + s.soundMismatches
         + s.underlayMismatches + s.unknownTableIds + mBuilder.UnknownUnderlays() + s.createdNotInPacket + s.packetCreatedNotRebuilt
         + s.blueprintMismatches + s.eraseMismatches + s.deleteMismatches + s.packetUpdatesDropped
         + s.unitChangesWithoutUpdate + s.unitConstantsMissing + s.meshMismatches + s.meshResourceMismatches
         + s.positionsOutOfRange + s.tickMismatches;
  }

  std::string CLoopbackLink::Summary(const char* const when) const
  {
    const SRebuildStats& s = mRebuilder.Stats();
    const double frames = s.frames != 0u ? static_cast<double>(s.frames) : 1.0;
    const auto u = [](const std::uint64_t value) { return static_cast<unsigned long long>(value); };
    std::string text = gpg::STR_Printf(
      "loopback %s: frames %llu, %.1f KB/s, encode failures %llu, decode failures %llu, rebuild failures %llu, "
      "created %llu, erased %llu, deleted %llu, entity updates %llu (settle %llu, packet data %llu), "
      "max position error %.5f, time per beat %.2f ms server + %.2f ms client (decode %.2f, delta %.2f, rebuild "
      "%.2f; max %.1f ms)",
      when, u(s.frames), static_cast<double>(s.frameBytes) / frames * 10.0 / 1024.0, u(mEncodeFailures),
      u(s.decodeFailures), u(mRebuildFailures), u(s.created), u(s.erased), u(s.deleted), u(s.entityUpdates),
      u(s.settleUpdates), u(s.entityDataBorrowed), s.maxPositionError, mServerSeconds * 1000.0 / frames,
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
      "mismatches %llu, unit stat items applied %llu",
      when, u(s.createdNotInPacket), u(s.packetCreatedNotRebuilt), u(s.blueprintMismatches), u(s.noBlueprint),
      u(s.eraseMismatches), u(s.deleteMismatches), u(s.packetUpdatesDropped), u(s.unitChangesWithoutUpdate),
      u(s.unitConstantsMissing), u(s.meshMismatches), u(s.meshResourceMismatches), u(s.positionsOutOfRange),
      u(s.soundMismatches), u(s.underlayMismatches), u(mBuilder.UnknownUnderlays()), u(s.unknownTableIds),
      u(mTableFailures), static_cast<double>(mTableBytes) / 1024.0, u(s.tickMismatches), u(s.statsApplied)
    ).c_str();
    return text;
  }
} // namespace faf::remote::client
