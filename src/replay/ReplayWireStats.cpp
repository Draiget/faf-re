#include "replay/ReplayWireStats.h"

#include <algorithm>

#include "moho/entity/REntityBlueprint.h"
#include "moho/sim/SimDriver.h"
#include "moho/unit/core/Unit.h"

// Engine addition, server mode: see ReplayWireStats.h.

namespace faf::replay
{
  namespace
  {
    namespace wire = faf::remote::wire;

    constexpr std::uint32_t kFullFrameEvery = 100; // beats between full-frame size samples

    /** Visibility mode, being-built and dead flags, and the layer, in the record's 16 bits. */
    [[nodiscard]] std::uint16_t PackFlags(const moho::SSTIEntityVariableData& data) noexcept
    {
      std::uint32_t flags = 0;
      flags |= data.mIsBeingBuilt != 0u ? 1u : 0u;
      flags |= data.mIsDead != 0u ? 2u : 0u;
      flags |= (static_cast<std::uint32_t>(data.mVisibilityMode) & 7u) << 2;
      flags |= (static_cast<std::uint32_t>(data.mLayerMask) & 0x7Fu) << 5;
      return static_cast<std::uint16_t>(flags);
    }

    void ApplyVariableData(
      wire::SEntityRecord& record, const moho::SSTIEntityVariableData& data, const wire::SFrameCodec& codec
    )
    {
      const auto& pos = data.mCurTransform.pos_;
      const auto& orient = data.mCurTransform.orient_;
      record.position = {codec.position.x.Encode(pos.x), codec.position.y.Encode(pos.y), codec.position.z.Encode(pos.z)};
      record.orientation = wire::PackQuaternion({orient.x, orient.y, orient.z, orient.w});
      record.health = data.mHealth;
      record.maxHealth = data.mMaxHealth;
      record.fractionComplete = data.mFractionComplete;
      record.flags = PackFlags(data);
    }
  } // namespace

  CReplayWireStats::CReplayWireStats(
    const std::string& path, const faf::remote::wire::SContentTables& tables, const float mapSizeX,
    const float mapSizeZ
  )
    : mTables(tables)
  {
    mCodec.position = wire::SPositionQuantizer::ForMap(mapSizeX, mapSizeZ);
    mCodec.maxEntities = 1u << 20;
    if (fopen_s(&mFile, path.c_str(), "w") != 0) {
      mFile = nullptr;
      return;
    }
    std::fprintf(mFile, "beat,entities,created,removed,changed,delta_bytes,full_bytes\n");
  }

  CReplayWireStats::~CReplayWireStats()
  {
    if (mFile != nullptr) {
      std::fclose(mFile);
    }
  }

  void CReplayWireStats::OnPacket(const moho::SSyncData& packet)
  {
    // `CWldSession::DoBeat`'s order: creations, updates, erases, deletes.
    const auto create = [&](const moho::SCreateEntityParams& params) {
      wire::SEntityRecord record{};
      record.id = params.mEntityId;
      if (params.mBlueprint != nullptr) {
        record.blueprint = mTables.blueprints.Ordinal(params.mBlueprint->mBlueprintId.c_str());
        if (record.blueprint == wire::COrdinalTable::kNone) {
          ++mUnknownBlueprints;
        }
      }
      mWorld[record.id] = record;
    };
    for (const moho::SCreateEntityParams& params : packet.mNewEntities) {
      create(params);
    }
    for (const moho::SCreateUnitParams& params : packet.mNewUnits) {
      create(params);
    }
    for (const moho::SEntityVariableUpdateEntry& update : packet.mEntityUpdates) {
      const auto it = mWorld.find(static_cast<std::uint32_t>(update.mEntityId));
      if (it != mWorld.end()) {
        ApplyVariableData(it->second, update.mVariableData, mCodec);
      }
    }
    for (const moho::EntId id : packet.mEraseIds) {
      mWorld.erase(static_cast<std::uint32_t>(id));
    }
    for (const moho::EntId id : packet.mDeleteIds) {
      mWorld.erase(static_cast<std::uint32_t>(id));
    }
    Measure(static_cast<std::uint32_t>(packet.mCurBeat));
  }

  void CReplayWireStats::Measure(const std::uint32_t beat)
  {
    wire::SViewFrame frame{};
    frame.frameId = mNextFrameId++;
    frame.beat = beat;
    frame.entities.reserve(mWorld.size());
    for (const auto& [id, record] : mWorld) {
      frame.entities.push_back(record);
    }

    const wire::SViewFrame* const baseline = mHavePrevious ? &mPrevious : nullptr;
    wire::BitWriter writer;
    if (!wire::EncodeFrame(frame, baseline, mCodec, writer)) {
      ++mEncodeFailures;
      return;
    }
    wire::BitReader reader(writer.Bytes());
    wire::SViewFrame decoded{};
    if (!wire::DecodeFrame(reader, baseline, mCodec, decoded) || !(decoded == frame)) {
      ++mRoundTripFailures;
    }

    const wire::SFrameDelta delta = wire::ComputeFrameDelta(baseline, frame);
    const auto deltaBytes = static_cast<std::uint32_t>(writer.Bytes().size());
    std::uint32_t fullBytes = 0;
    if (beat % kFullFrameEvery == 0u) {
      wire::BitWriter full;
      if (wire::EncodeFrame(frame, nullptr, mCodec, full)) {
        fullBytes = static_cast<std::uint32_t>(full.Bytes().size());
        mFullBytesSum += fullBytes;
        ++mFullSamples;
      }
    }

    ++mBeats;
    mDeltaBytes += deltaBytes;
    mDeltaSizes.push_back(deltaBytes);
    mEntitySum += frame.entities.size();
    mMaxEntities = std::max(mMaxEntities, static_cast<std::uint32_t>(frame.entities.size()));
    if (mFile != nullptr) {
      std::fprintf(
        mFile, "%u,%zu,%zu,%zu,%zu,%u,%u\n", beat, frame.entities.size(), delta.created.size(), delta.removed.size(),
        delta.changed.size(), deltaBytes, fullBytes
      );
    }
    mPrevious = std::move(frame);
    mHavePrevious = true;
  }

  std::string CReplayWireStats::Summary() const
  {
    std::vector<std::uint32_t> sizes = mDeltaSizes;
    std::sort(sizes.begin(), sizes.end());
    const auto percentile = [&](const double p) -> std::uint32_t {
      return sizes.empty() ? 0u : sizes[static_cast<std::size_t>(p * static_cast<double>(sizes.size() - 1))];
    };
    char text[512];
    std::snprintf(
      text, sizeof(text),
      "wire entities lane: %llu beats, entities mean %.0f max %u, delta bytes/beat mean %.0f p50 %u p95 %u max %u "
      "(%.1f KB/s at 10 beats/s), full frame mean %.0f bytes, round-trip failures %llu, encode failures %llu, "
      "unknown blueprints %llu",
      static_cast<unsigned long long>(mBeats), mBeats != 0 ? static_cast<double>(mEntitySum) / mBeats : 0.0,
      mMaxEntities, mBeats != 0 ? static_cast<double>(mDeltaBytes) / mBeats : 0.0, percentile(0.5), percentile(0.95),
      sizes.empty() ? 0u : sizes.back(), mBeats != 0 ? static_cast<double>(mDeltaBytes) / mBeats * 10.0 / 1000.0 : 0.0,
      mFullSamples != 0 ? static_cast<double>(mFullBytesSum) / mFullSamples : 0.0,
      static_cast<unsigned long long>(mRoundTripFailures), static_cast<unsigned long long>(mEncodeFailures),
      static_cast<unsigned long long>(mUnknownBlueprints)
    );
    return text;
  }
} // namespace faf::replay
