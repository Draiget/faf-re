#include "replay/ReplayWireStats.h"

#include <algorithm>
#include <array>

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
      const std::array<float, 4> quaternion{orient.x, orient.y, orient.z, orient.w};
      record.yawOnly = wire::IsYawOnly(quaternion);
      record.orientation = record.yawOnly ? wire::QuantizeYaw(quaternion) : wire::PackQuaternion(quaternion);
      record.health = data.mHealth;
      record.maxHealth = data.mMaxHealth;
      record.fractionComplete = data.mFractionComplete;
      record.flags = PackFlags(data);
    }
    [[nodiscard]] std::uint16_t SiloCount(const std::int32_t count) noexcept
    {
      return static_cast<std::uint16_t>(count < 0 ? 0 : (count > 0xFFFF ? 0xFFFF : count));
    }

    void ApplyUnitData(wire::SUnitFields& unit, const moho::SSTIUnitVariableData& data)
    {
      unit.fuelRatio = data.mFuelRatio;
      unit.shieldRatio = data.mShieldRatio;
      unit.workProgress = data.mWorkProgress;
      unit.unitStates = data.mUnitStates;
      unit.scriptBits = data.mScriptbits;
      unit.siloCounts = {
        SiloCount(data.mTacticalSiloBuildCount), SiloCount(data.mNukeSiloBuildCount),
        SiloCount(data.mTacticalSiloStorageCount), SiloCount(data.mNukeSiloStorageCount)
      };
      unit.unitFlags = static_cast<std::uint8_t>(
        (data.mIsPaused ? 1u : 0u) | (data.mAutoMode ? 2u : 0u) | (data.mAutoSurfaceMode ? 4u : 0u)
        | (data.mIsBusy ? 8u : 0u) | (data.mRepeatQueue ? 16u : 0u) | (data.mIsValidTarget ? 32u : 0u)
        | (data.mOverchargePaused ? 64u : 0u)
      );
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
    mDeadReckoningCodec = mCodec;
    mDeadReckoningCodec.deadReckoning = true;
    mDeadReckoning[0].tolerance = 4;  // 1/16 world unit
    mDeadReckoning[1].tolerance = 16; // 1/4 world unit
    if (fopen_s(&mFile, path.c_str(), "w") != 0) {
      mFile = nullptr;
      return;
    }
    std::fprintf(
      mFile, "beat,entities,created,removed,changed,delta_bytes,full_bytes,delta_bytes_no_yaw,delta_bytes_no_units\n"
    );
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
      mWorld[params.mEntityId].isUnit = true;
    }
    for (const moho::SEntityVariableUpdateEntry& update : packet.mEntityUpdates) {
      const auto it = mWorld.find(static_cast<std::uint32_t>(update.mEntityId));
      if (it != mWorld.end()) {
        ApplyVariableData(it->second, update.mVariableData, mCodec);
      }
    }
    for (const moho::SUnitVariableUpdateEntry& update : packet.mUnitUpdates) {
      const auto it = mWorld.find(static_cast<std::uint32_t>(update.mEntityId));
      if (it != mWorld.end() && it->second.isUnit) {
        ApplyUnitData(it->second.unit, update.mVariableData);
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
    AccountFieldBits(delta);
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

    // Comparison encodings: yaw-only rotations as full quaternions, and no unit block.
    wire::SViewFrame noYaw = frame;
    wire::SViewFrame noUnits = frame;
    for (wire::SEntityRecord& record : noYaw.entities) {
      if (record.yawOnly) {
        ++mYawOnlyRecords;
        record.orientation = wire::PackQuaternion(wire::YawToQuaternion(record.orientation));
        record.yawOnly = false;
      }
    }
    for (wire::SEntityRecord& record : noUnits.entities) {
      if (record.isUnit) {
        ++mUnitRecords;
        record.isUnit = false;
        record.unit = {};
      }
    }
    const auto encodedSize = [&](const wire::SViewFrame& variant, const wire::SViewFrame& previous) -> std::uint32_t {
      wire::BitWriter variantWriter;
      return wire::EncodeFrame(variant, mHavePrevious ? &previous : nullptr, mCodec, variantWriter)
               ? static_cast<std::uint32_t>(variantWriter.Bytes().size())
               : 0u;
    };
    const std::uint32_t noYawBytes = encodedSize(noYaw, mPreviousNoYaw);
    const std::uint32_t noUnitBytes = encodedSize(noUnits, mPreviousNoUnits);
    mDeltaBytesNoYaw += noYawBytes;
    mDeltaBytesNoUnits += noUnitBytes;
    mPreviousNoYaw = std::move(noYaw);
    mPreviousNoUnits = std::move(noUnits);

    // Dead-reckoned variants: each view record keeps its anchor while the client's prediction
    // stays within the tolerance of the sim's position.
    for (SDeadReckoningVariant& variant : mDeadReckoning) {
      wire::SViewFrame reckoned = frame;
      std::map<std::uint32_t, std::pair<wire::SEntityRecord, wire::QuantizedPosition>> next;
      for (wire::SEntityRecord& record : reckoned.entities) {
        const wire::QuantizedPosition actual = record.position;
        auto found = variant.sent.find(record.id);
        if (found == variant.sent.end()) {
          record.anchorBeat = beat; // anchored where it is created, at rest
        } else {
          wire::SEntityRecord anchored = found->second.first;
          if (wire::ApplyDeadReckoning(
                anchored, actual, found->second.second, beat, variant.tolerance, mDeadReckoningCodec
              )) {
            ++variant.reanchors;
          }
          record.position = anchored.position;
          record.velocity = anchored.velocity;
          record.anchorBeat = anchored.anchorBeat;
        }
        next.emplace(record.id, std::make_pair(record, actual));
      }
      variant.sent = std::move(next);
      wire::BitWriter variantWriter;
      if (wire::EncodeFrame(
            reckoned, mHavePrevious ? &variant.previous : nullptr, mDeadReckoningCodec, variantWriter
          )) {
        variant.bytes += variantWriter.Bytes().size();
      }
      variant.previous = std::move(reckoned);
    }

    ++mBeats;
    mDeltaBytes += deltaBytes;
    mDeltaSizes.push_back(deltaBytes);
    mEntitySum += frame.entities.size();
    mMaxEntities = std::max(mMaxEntities, static_cast<std::uint32_t>(frame.entities.size()));
    if (mFile != nullptr) {
      std::fprintf(
        mFile, "%u,%zu,%zu,%zu,%zu,%u,%u,%u,%u\n", beat, frame.entities.size(), delta.created.size(),
        delta.removed.size(), delta.changed.size(), deltaBytes, fullBytes, noYawBytes, noUnitBytes
      );
    }
    mPrevious = std::move(frame);
    mHavePrevious = true;
  }

  void CReplayWireStats::AccountFieldBits(const faf::remote::wire::SFrameDelta& delta)
  {
    // The widths the encoder writes (EntityFrame.cpp), so the classes add up to its payload.
    const auto varintBits = [](std::uint32_t value) -> std::uint64_t {
      std::uint64_t groups = 1;
      while (value >= 0x80u) {
        value >>= 7;
        ++groups;
      }
      return 8u * groups;
    };
    const std::uint64_t positionBits = static_cast<std::uint64_t>(mCodec.position.x.bits) + mCodec.position.y.bits
                                     + mCodec.position.z.bits;
    const auto fieldBits = [&](const wire::SEntityRecord& record, const std::uint16_t fields, SFieldBits& into) {
      if ((fields & wire::kFieldPosition) != 0u) into.transform += positionBits;
      if ((fields & wire::kFieldOrientation) != 0u) into.transform += 1u + (record.yawOnly ? 16u : 32u);
      if ((fields & wire::kFieldHealth) != 0u) into.scalars += 32;
      if ((fields & wire::kFieldMaxHealth) != 0u) into.scalars += 32;
      if ((fields & wire::kFieldFraction) != 0u) into.scalars += 32;
      if ((fields & wire::kFieldFlags) != 0u) into.flags += 16;
      if ((fields & wire::kFieldKind) != 0u) into.flags += 1;
      if ((fields & wire::kFieldBlueprint) != 0u) into.flags += varintBits(record.blueprint);
      if ((fields & wire::kFieldArmy) != 0u) into.flags += 8;
      if (record.isUnit) {
        if ((fields & wire::kFieldUnitFuel) != 0u) into.unit += 32;
        if ((fields & wire::kFieldUnitShield) != 0u) into.unit += 32;
        if ((fields & wire::kFieldUnitWork) != 0u) into.unit += 32;
        if ((fields & wire::kFieldUnitStates) != 0u) into.unit += 64;
        if ((fields & wire::kFieldUnitScriptBits) != 0u) into.unit += 32;
        if ((fields & wire::kFieldUnitSilos) != 0u) into.unit += 64;
        if ((fields & wire::kFieldUnitFlags) != 0u) into.unit += 8;
      }
    };
    const auto gap = [&](bool& first, std::uint32_t& previous, const std::uint32_t id) -> std::uint64_t {
      const std::uint64_t bits = varintBits(first ? id : id - previous - 1u);
      first = false;
      previous = id;
      return bits;
    };

    bool first = true;
    std::uint32_t previous = 0;
    for (const std::uint32_t id : delta.removed) {
      mFieldBits.removals += gap(first, previous, id);
    }
    first = true;
    for (const wire::SEntityRecord& record : delta.created) {
      SFieldBits created{};
      fieldBits(record, wire::CreationFields(record), created);
      mFieldBits.creations +=
        gap(first, previous, record.id) + created.transform + created.scalars + created.flags + created.unit;
    }
    first = true;
    for (const wire::SFrameDelta::SChange& change : delta.changed) {
      mFieldBits.overhead += gap(first, previous, change.record.id) + varintBits(change.fields);
      fieldBits(change.record, change.fields, mFieldBits);
    }
  }

  std::string CReplayWireStats::Summary() const
  {
    std::vector<std::uint32_t> sizes = mDeltaSizes;
    std::sort(sizes.begin(), sizes.end());
    const auto percentile = [&](const double p) -> std::uint32_t {
      return sizes.empty() ? 0u : sizes[static_cast<std::size_t>(p * static_cast<double>(sizes.size() - 1))];
    };
    const auto rate = [&](const std::uint64_t bits) -> double {
      return mBeats != 0 ? static_cast<double>(bits) / 8.0 / static_cast<double>(mBeats) * 10.0 / 1000.0 : 0.0;
    };
    char text[1024];
    std::snprintf(
      text, sizeof(text),
      "wire entities lane: %llu beats, entities mean %.0f max %u, delta bytes/beat mean %.0f p50 %u p95 %u max %u "
      "(%.1f KB/s at 10 beats/s), full frame mean %.0f bytes, round-trip failures %llu, encode failures %llu, "
      "unknown blueprints %llu; without the yaw form %.1f KB/s (yaw-only records %.0f%%), without the unit block "
      "%.1f KB/s; by field (KB/s): transforms %.1f, scalars %.1f, flags %.1f, unit block %.1f, ids and masks %.1f, "
      "creations %.1f, removals %.1f; dead reckoning (WP7.5) at 4 steps %.1f KB/s (%.2f re-anchors per entity-beat), "
      "at 16 steps %.1f KB/s (%.2f)",
      static_cast<unsigned long long>(mBeats), mBeats != 0 ? static_cast<double>(mEntitySum) / mBeats : 0.0,
      mMaxEntities, mBeats != 0 ? static_cast<double>(mDeltaBytes) / mBeats : 0.0, percentile(0.5), percentile(0.95),
      sizes.empty() ? 0u : sizes.back(), mBeats != 0 ? static_cast<double>(mDeltaBytes) / mBeats * 10.0 / 1000.0 : 0.0,
      mFullSamples != 0 ? static_cast<double>(mFullBytesSum) / mFullSamples : 0.0,
      static_cast<unsigned long long>(mRoundTripFailures), static_cast<unsigned long long>(mEncodeFailures),
      static_cast<unsigned long long>(mUnknownBlueprints),
      mBeats != 0 ? static_cast<double>(mDeltaBytesNoYaw) / mBeats * 10.0 / 1000.0 : 0.0,
      mEntitySum != 0 ? 100.0 * static_cast<double>(mYawOnlyRecords) / static_cast<double>(mEntitySum) : 0.0,
      mBeats != 0 ? static_cast<double>(mDeltaBytesNoUnits) / mBeats * 10.0 / 1000.0 : 0.0, rate(mFieldBits.transform),
      rate(mFieldBits.scalars), rate(mFieldBits.flags), rate(mFieldBits.unit), rate(mFieldBits.overhead),
      rate(mFieldBits.creations), rate(mFieldBits.removals), rate(mDeadReckoning[0].bytes * 8u),
      mEntitySum != 0 ? static_cast<double>(mDeadReckoning[0].reanchors) / static_cast<double>(mEntitySum) : 0.0,
      rate(mDeadReckoning[1].bytes * 8u),
      mEntitySum != 0 ? static_cast<double>(mDeadReckoning[1].reanchors) / static_cast<double>(mEntitySum) : 0.0
    );
    return text;
  }
} // namespace faf::replay
