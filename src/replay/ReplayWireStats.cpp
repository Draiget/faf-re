#include "replay/ReplayWireStats.h"

#include <algorithm>
#include <array>
#include <bit>

#include "moho/sim/SimDriver.h"
#include "moho/sim/STIMap.h"

// Engine addition, server mode: see ReplayWireStats.h.

namespace faf::replay
{
  namespace
  {
    namespace wire = faf::remote::wire;

    constexpr std::uint32_t kFullFrameEvery = 100; // beats between full-frame size samples

  } // namespace

  namespace
  {
    [[nodiscard]] faf::remote::wire::SFrameCodec MakeCodec(const float mapSizeX, const float mapSizeZ)
    {
      faf::remote::wire::SFrameCodec codec{};
      codec.position = faf::remote::wire::SPositionQuantizer::ForMap(mapSizeX, mapSizeZ);
      codec.maxEntities = 1u << 20;
      return codec;
    }
  } // namespace

  CReplayWireStats::CReplayWireStats(
    const std::string& path, const faf::remote::wire::SContentTables& tables, const float mapSizeX,
    const float mapSizeZ
  )
    : mTables(tables)
    , mCodec(MakeCodec(mapSizeX, mapSizeZ))
    , mBuilder(tables, mCodec)
  {
    const auto variant = [&](const char* name, const std::uint32_t tolerance, const std::uint32_t window,
                             const std::uint32_t fractionBits, const bool bend, const std::uint32_t turnTolerance,
                             const bool ground = false) {
      wire::SFrameCodec codec = mCodec;
      codec.deadReckoning = true;
      codec.velocityFractionBits = fractionBits;
      codec.orientationReckoning = turnTolerance != 0u;
      codec.groundFollowing = ground;
      codec.ground = ground ? &mGround : nullptr;
      wire::SReckoningScheme scheme{};
      scheme.tolerance = tolerance;
      scheme.window = window;
      scheme.verticalAcceleration = bend;
      scheme.orientationTolerance = turnTolerance;
      scheme.followGround = ground;
      mDeadReckoning.push_back(SDeadReckoningVariant{name, codec, faf::remote::CDeadReckoner(scheme), {}, 0});
    };
    variant("WP7.5 4 steps", 4, 1, 0, false, 0);
    variant("WP7.5 16 steps", 16, 1, 0, false, 0);
    variant("fit 4 steps", 4, 8, 4, false, 0);
    variant("fit+bend 4 steps", 4, 8, 4, true, 0);
    variant("fit+bend 4 steps, turns 0.35 deg", 4, 8, 4, true, 64);
    variant("fit+bend 4 steps, turns 1 deg", 4, 8, 4, true, 182);
    variant("WP7.5+ground 4 steps", 4, 1, 0, false, 0, true);
    variant("fit+bend+ground 4 steps", 4, 8, 4, true, 0, true);
    variant("WP7.5+ground 4 steps, turns 1 deg", 4, 1, 0, false, 182, true);
    variant("WP7.5+ground 16 steps, turns 1 deg", 16, 1, 0, false, 182, true);
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
    mGround.SetField(packet.mTerrainUpdate.px);
    mBuilder.Apply(packet);
    Measure(static_cast<std::uint32_t>(packet.mCurBeat));
  }

  void CReplayWireStats::Measure(const std::uint32_t beat)
  {
    wire::SViewFrame frame = mBuilder.Build(beat);

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
      variant.reckoner.Apply(reckoned, variant.codec);
      wire::BitWriter variantWriter;
      if (wire::EncodeFrame(reckoned, mHavePrevious ? &variant.previous : nullptr, variant.codec, variantWriter)) {
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
    const auto fieldBits = [&](const wire::SEntityRecord& record, const std::uint32_t fields, SFieldBits& into) {
      if ((fields & wire::kFieldPosition) != 0u) {
        into.transform += 1u + (record.farPosition ? 96u : positionBits);
      }
      if ((fields & wire::kFieldOrientation) != 0u) {
        into.transform += 1u + (record.yawOnly ? 16u : 32u);
        into.orientation += 1u + (record.yawOnly ? 16u : 32u);
      }
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
        const auto zz = [&](const std::int32_t value) {
          return varintBits((static_cast<std::uint32_t>(value) << 1) ^ static_cast<std::uint32_t>(value >> 31));
        };
        const auto categories = [&](const wire::SCategoryBits& bits) {
          return varintBits(bits.firstWord) + varintBits(static_cast<std::uint32_t>(bits.words.size())) + 32u * bits.words.size();
        };
        const wire::SUnitFields& unit = record.unit;
        if ((fields & wire::kFieldUnitStats) != 0u) {
          std::uint64_t bits = varintBits(static_cast<std::uint32_t>(unit.stats->size()));
          for (const wire::SUnitStat& stat : *unit.stats) {
            bits += varintBits(stat.name) + 3u + (stat.type == wire::SUnitStat::kString ? varintBits(stat.text + 1u) : 32u);
          }
          into.unitParts[0] += bits;
        }
        if ((fields & wire::kFieldUnitConstants) != 0u) into.unitParts[1] += 16;
        const wire::SUnitDetail& d = *unit.detail;
        if ((fields & wire::kFieldUnitDetail) != 0u) {
          into.unitParts[2] += varintBits(d.creator) + zz(d.creationTick) + zz(d.stunTicks) + zz(d.jobType)
                             + zz(d.fireState) + zz(d.siloMaxStorage[0]) + zz(d.siloMaxStorage[1])
                             + varintBits(d.selectionInheritor) + varintBits(d.customName + 1u) + varintBits(d.focusUnit)
                             + varintBits(d.guardedUnit) + varintBits(d.targetBlip) + 8u + zz(d.reconFlags);
        }
        if ((fields & wire::kFieldUnitEconomy) != 0u) {
          into.unitParts[3] += 192;
          // How many of the six floats changed (a mask inside the economy would send only those).
          if (&into == &mFieldBits && mHavePrevious) {
            const auto it = std::lower_bound(
              mPrevious.entities.begin(), mPrevious.entities.end(), record.id,
              [](const wire::SEntityRecord& r, const std::uint32_t id) { return r.id < id; }
            );
            if (it != mPrevious.entities.end() && it->id == record.id && it->isUnit) {
              std::uint32_t changed = 0;
              for (std::size_t i = 0; i < 6; ++i) {
                changed += std::bit_cast<std::uint32_t>(record.unit.detail->economy[i])
                               != std::bit_cast<std::uint32_t>(it->unit.detail->economy[i])
                             ? 1u
                             : 0u;
              }
              ++mEconomyChanges;
              mEconomyFloatsChanged += changed;
            }
          }
        }
        if ((fields & wire::kFieldUnitQueues) != 0u) {
          std::uint64_t bits = varintBits(static_cast<std::uint32_t>(d.commands.size()))
                             + varintBits(static_cast<std::uint32_t>(d.buildQueue.size()));
          for (const std::int32_t id : d.commands) bits += zz(id);
          for (const std::int32_t id : d.buildQueue) bits += zz(id);
          into.unitParts[4] += bits;
        }
        if ((fields & wire::kFieldUnitWeapons) != 0u) {
          std::uint64_t bits = varintBits(static_cast<std::uint32_t>(d.weapons.size()));
          for (const wire::SUnitWeapon& w : d.weapons) {
            bits += categories(w.targets) + categories(w.secondary) + varintBits(w.layer) + 96u
                  + varintBits(w.minRangeVisual + 1u) + varintBits(w.maxRangeVisual + 1u);
          }
          into.unitParts[5] += bits;
        }
        if ((fields & wire::kFieldUnitAttributes) != 0u) {
          into.unitParts[6] += varintBits(d.attributes.blueprint + 1u) + 32u + categories(d.attributes.restriction) + 384u
                             + 64u + 32u + 32u;
        }
      }
      const wire::SAppearance& look = record.appearance;
      if ((fields & wire::kFieldMesh) != 0u) into.appearance[0] += varintBits(look.mesh);
      if ((fields & wire::kFieldScale) != 0u) into.appearance[1] += 96;
      if ((fields & wire::kFieldAttachment) != 0u) {
        into.appearance[2] += 32u + varintBits(static_cast<std::uint32_t>(look.attachments.size())) + 32u * look.attachments.size();
      }
      if ((fields & wire::kFieldVisualFlags) != 0u) into.appearance[3] += 5;
      if ((fields & wire::kFieldImpact) != 0u) into.appearance[4] += 32;
      if ((fields & wire::kFieldScroll) != 0u) {
        // As the encoder: one bit, then the end alone when the start is the baseline's end.
        const wire::SEntityRecord* before = nullptr;
        if (mHavePrevious) {
          const auto it = std::lower_bound(
            mPrevious.entities.begin(), mPrevious.entities.end(), record.id,
            [](const wire::SEntityRecord& r, const std::uint32_t id) { return r.id < id; }
          );
          if (it != mPrevious.entities.end() && it->id == record.id) {
            before = &*it;
          }
        }
        const bool shifted = before != nullptr
                          && std::bit_cast<std::uint32_t>(look.scroll[0]) == std::bit_cast<std::uint32_t>(before->appearance.scroll[2])
                          && std::bit_cast<std::uint32_t>(look.scroll[1]) == std::bit_cast<std::uint32_t>(before->appearance.scroll[3]);
        into.appearance[5] += shifted ? 65u : 129u;
      }
      if ((fields & wire::kFieldIntel) != 0u) {
        for (const std::uint32_t radius : look.intel) {
          into.appearance[6] += varintBits(radius);
        }
      }
    };
    const auto sum = [](const SFieldBits& bits) {
      std::uint64_t total = bits.transform + bits.scalars + bits.flags + bits.unit;
      for (const std::uint64_t part : bits.appearance) {
        total += part;
      }
      for (const std::uint64_t part : bits.unitParts) {
        total += part;
      }
      return total;
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
      const std::uint32_t fields = wire::CreationFields(record);
      mFieldBits.creations += gap(first, previous, record.id) + varintBits(fields) + varintBits(record.tickCreated) + sum(created);
      for (std::size_t i = 0; i < created.appearance.size(); ++i) {
        mCreationAppearanceBits[i] += created.appearance[i];
      }
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
    char text[3072];
    std::snprintf(
      text, sizeof(text),
      "wire entities lane: %llu beats, entities mean %.0f max %u, delta bytes/beat mean %.0f p50 %u p95 %u max %u "
      "(%.1f KB/s at 10 beats/s), full frame mean %.0f bytes, round-trip failures %llu, encode failures %llu, "
      "unknown blueprints %llu; without the yaw form %.1f KB/s (yaw-only records %.0f%%), without the unit block "
      "%.1f KB/s; by field (KB/s): transforms %.1f (orientation %.1f), scalars %.1f, flags %.1f, unit block %.1f, ids and masks %.1f, "
      "creations %.1f, removals %.1f; dead reckoning (WP7.5) at 4 steps %.1f KB/s (%.2f re-anchors per entity-beat), "
      "at 16 steps %.1f KB/s (%.2f); appearance changes (KB/s) mesh %.2f scale %.2f attachments %.2f visual %.2f "
      "impact %.2f scroll %.2f intel %.2f; appearance in creations (KB/s) mesh %.2f scale %.2f attachments %.2f "
      "visual %.2f impact %.2f scroll %.2f intel %.2f; unit block parts in changes (KB/s) stats %.2f constants %.2f "
      "detail %.2f economy %.2f queues %.2f weapons %.2f attributes %.2f",
      static_cast<unsigned long long>(mBeats), mBeats != 0 ? static_cast<double>(mEntitySum) / mBeats : 0.0,
      mMaxEntities, mBeats != 0 ? static_cast<double>(mDeltaBytes) / mBeats : 0.0, percentile(0.5), percentile(0.95),
      sizes.empty() ? 0u : sizes.back(), mBeats != 0 ? static_cast<double>(mDeltaBytes) / mBeats * 10.0 / 1000.0 : 0.0,
      mFullSamples != 0 ? static_cast<double>(mFullBytesSum) / mFullSamples : 0.0,
      static_cast<unsigned long long>(mRoundTripFailures), static_cast<unsigned long long>(mEncodeFailures),
      static_cast<unsigned long long>(mBuilder.UnknownBlueprints()),
      mBeats != 0 ? static_cast<double>(mDeltaBytesNoYaw) / mBeats * 10.0 / 1000.0 : 0.0,
      mEntitySum != 0 ? 100.0 * static_cast<double>(mYawOnlyRecords) / static_cast<double>(mEntitySum) : 0.0,
      mBeats != 0 ? static_cast<double>(mDeltaBytesNoUnits) / mBeats * 10.0 / 1000.0 : 0.0, rate(mFieldBits.transform),
      rate(mFieldBits.orientation),
      rate(mFieldBits.scalars), rate(mFieldBits.flags), rate(mFieldBits.unit), rate(mFieldBits.overhead),
      rate(mFieldBits.creations), rate(mFieldBits.removals), rate(mDeadReckoning[0].bytes * 8u),
      mEntitySum != 0 ? static_cast<double>(mDeadReckoning[0].reckoner.Reanchors()) / static_cast<double>(mEntitySum) : 0.0,
      rate(mDeadReckoning[1].bytes * 8u),
      mEntitySum != 0 ? static_cast<double>(mDeadReckoning[1].reckoner.Reanchors()) / static_cast<double>(mEntitySum) : 0.0,
      rate(mFieldBits.appearance[0]), rate(mFieldBits.appearance[1]), rate(mFieldBits.appearance[2]),
      rate(mFieldBits.appearance[3]), rate(mFieldBits.appearance[4]), rate(mFieldBits.appearance[5]),
      rate(mFieldBits.appearance[6]), rate(mCreationAppearanceBits[0]), rate(mCreationAppearanceBits[1]),
      rate(mCreationAppearanceBits[2]), rate(mCreationAppearanceBits[3]), rate(mCreationAppearanceBits[4]),
      rate(mCreationAppearanceBits[5]), rate(mCreationAppearanceBits[6]), rate(mFieldBits.unitParts[0]),
      rate(mFieldBits.unitParts[1]), rate(mFieldBits.unitParts[2]), rate(mFieldBits.unitParts[3]),
      rate(mFieldBits.unitParts[4]), rate(mFieldBits.unitParts[5]), rate(mFieldBits.unitParts[6])
    );
    std::string summary = text;
    {
      const faf::remote::CDeadReckoner::SReanchorCauses& c = mDeadReckoning.front().reckoner.Causes();
      const double all = mDeadReckoning.front().reckoner.Reanchors() != 0u
                           ? static_cast<double>(mDeadReckoning.front().reckoner.Reanchors())
                           : 1.0;
      char causes[400];
      std::snprintf(
        causes, sizeof(causes),
        "; re-anchors at 4 steps (WP7.5): horizontal only %.0f%%, vertical only %.0f%%, both %.0f%%, units %.0f%%, "
        "stopped %.0f%%, after 1 beat %.0f%%, 2-3 %.0f%%, 4-9 %.0f%%, 10+ %.0f%%",
        100.0 * c.horizontalOnly / all, 100.0 * c.verticalOnly / all, 100.0 * c.both / all, 100.0 * c.units / all,
        100.0 * c.stopped / all, 100.0 * c.afterBeats[0] / all, 100.0 * c.afterBeats[1] / all,
        100.0 * c.afterBeats[2] / all, 100.0 * c.afterBeats[3] / all
      );
      summary += causes;
    }
    {
      char economy[160];
      std::snprintf(
        economy, sizeof(economy), "; economy changes %llu, floats changed per change %.2f of 6",
        static_cast<unsigned long long>(mEconomyChanges),
        mEconomyChanges != 0u ? static_cast<double>(mEconomyFloatsChanged) / static_cast<double>(mEconomyChanges) : 0.0
      );
      summary += economy;
    }
    summary += "; dead reckoning schemes (WP7.8):";
    for (const SDeadReckoningVariant& variant : mDeadReckoning) {
      char part[240];
      const double entityBeats = mEntitySum != 0 ? static_cast<double>(mEntitySum) : 1.0;
      std::snprintf(
        part, sizeof(part), " %s %.1f KB/s (%.3f position, %.3f orientation re-anchors per entity-beat, %.0f%% of "
        "the position ones onto the ground);", variant.name,
        rate(variant.bytes * 8u), static_cast<double>(variant.reckoner.Reanchors()) / entityBeats,
        static_cast<double>(variant.reckoner.OrientationReanchors()) / entityBeats,
        variant.reckoner.Reanchors() != 0u
          ? 100.0 * static_cast<double>(variant.reckoner.GroundAnchors()) / static_cast<double>(variant.reckoner.Reanchors())
          : 0.0
      );
      summary += part;
    }
    return summary;
  }
} // namespace faf::replay
