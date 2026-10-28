#include "headless/ReplayBoneStats.h"

#include <algorithm>
#include <bit>
#include <cmath>

#include "moho/animation/CAniPose.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/sim/SimDriver.h"
#include "moho/unit/core/Unit.h"

// Engine addition, server mode: see ReplayBoneStats.h.

namespace faf::headless
{
  namespace
  {
    /** §7.2 budgets a bone delta at 6 bytes. */
    constexpr double kBytesPerBoneDelta = 6.0;
    /** Below this a bone counts as unchanged for the tolerance column (world units / quaternion). */
    constexpr float kPositionTolerance = 1.0e-3f;
    constexpr float kRotationTolerance = 1.0e-4f;

    [[nodiscard]] bool SameBits(const moho::VTransform& a, const moho::VTransform& b) noexcept
    {
      const float av[7] = {a.orient_.w, a.orient_.x, a.orient_.y, a.orient_.z, a.pos_.x, a.pos_.y, a.pos_.z};
      const float bv[7] = {b.orient_.w, b.orient_.x, b.orient_.y, b.orient_.z, b.pos_.x, b.pos_.y, b.pos_.z};
      for (int i = 0; i < 7; ++i) {
        if (std::bit_cast<std::uint32_t>(av[i]) != std::bit_cast<std::uint32_t>(bv[i])) {
          return false;
        }
      }
      return true;
    }

    [[nodiscard]] bool WithinTolerance(const moho::VTransform& a, const moho::VTransform& b) noexcept
    {
      return std::fabs(a.pos_.x - b.pos_.x) < kPositionTolerance && std::fabs(a.pos_.y - b.pos_.y) < kPositionTolerance
          && std::fabs(a.pos_.z - b.pos_.z) < kPositionTolerance
          && std::fabs(a.orient_.w - b.orient_.w) < kRotationTolerance
          && std::fabs(a.orient_.x - b.orient_.x) < kRotationTolerance
          && std::fabs(a.orient_.y - b.orient_.y) < kRotationTolerance
          && std::fabs(a.orient_.z - b.orient_.z) < kRotationTolerance;
    }
  } // namespace

  CReplayBoneStats::CReplayBoneStats(const std::string& path)
    : mPath(path)
  {
    if (fopen_s(&mFile, path.c_str(), "w") != 0) {
      mFile = nullptr;
      return;
    }
    std::fprintf(mFile, "beat,units_with_pose,bones,changed_exact,changed_over_tolerance\n");
  }

  CReplayBoneStats::~CReplayBoneStats()
  {
    if (mFile != nullptr) {
      std::fclose(mFile);
    }
  }

  void CReplayBoneStats::OnPacket(const moho::SSyncData& packet)
  {
    for (const moho::SCreateUnitParams& params : packet.mNewUnits) {
      mUnits[params.mEntityId].blueprint =
        params.mBlueprint != nullptr ? params.mBlueprint->mBlueprintId.c_str() : std::string("?");
    }

    std::uint32_t unitsWithPose = 0;
    std::uint64_t bones = 0;
    std::uint32_t changedExact = 0;
    std::uint32_t changedTolerance = 0;
    for (const moho::SUnitVariableUpdateEntry& update : packet.mUnitUpdates) {
      const moho::CAniPose* const pose = update.mVariableData.mSharedPose.get();
      if (pose == nullptr) {
        continue;
      }
      SUnitPose& unit = mUnits[static_cast<std::uint32_t>(update.mEntityId)];
      if (unit.blueprint.empty()) {
        unit.blueprint = "?";
      }
      const auto& poseBones = pose->mBones;
      const std::size_t count = static_cast<std::size_t>(poseBones.end() - poseBones.begin());
      ++unitsWithPose;
      bones += count;

      std::uint32_t unitExact = 0;
      std::uint32_t unitTolerance = 0;
      const bool comparable = unit.bones.size() == count;
      std::size_t i = 0;
      for (const moho::CAniPoseBone& bone : poseBones) {
        if (comparable) {
          if (!SameBits(bone.mLocalTransform, unit.bones[i])) {
            ++unitExact;
            if (!WithinTolerance(bone.mLocalTransform, unit.bones[i])) {
              ++unitTolerance;
            }
          }
        }
        ++i;
      }
      unit.bones.assign(count, moho::VTransform{});
      i = 0;
      for (const moho::CAniPoseBone& bone : poseBones) {
        unit.bones[i++] = bone.mLocalTransform;
      }
      if (!comparable) {
        continue; // first pose of this unit: nothing to compare against
      }
      changedExact += unitExact;
      changedTolerance += unitTolerance;
      SBlueprintTotals& totals = mBlueprints[unit.blueprint];
      ++totals.unitBeats;
      totals.bones += count;
      totals.changedExact += unitExact;
      totals.changedOverTolerance += unitTolerance;
      totals.maxChanged = std::max(totals.maxChanged, unitTolerance);
    }

    for (const moho::EntId id : packet.mDeleteIds) {
      mUnits.erase(static_cast<std::uint32_t>(id));
    }
    for (const moho::EntId id : packet.mEraseIds) {
      mUnits.erase(static_cast<std::uint32_t>(id));
    }

    ++mBeats;
    mChangedPerBeat.push_back(changedTolerance);
    if (mFile != nullptr) {
      std::fprintf(
        mFile, "%d,%u,%llu,%u,%u\n", packet.mCurBeat, unitsWithPose, static_cast<unsigned long long>(bones), changedExact,
        changedTolerance
      );
    }
  }

  std::string CReplayBoneStats::Finish()
  {
    std::FILE* blueprintFile = nullptr;
    if (fopen_s(&blueprintFile, (mPath + ".blueprints.csv").c_str(), "w") == 0 && blueprintFile != nullptr) {
      std::fprintf(
        blueprintFile,
        "blueprint,unit_beats,bones_per_unit,changed_exact_per_unit_beat,changed_over_tolerance_per_unit_beat,"
        "max_changed_over_tolerance\n"
      );
      for (const auto& [name, totals] : mBlueprints) {
        const double n = static_cast<double>(totals.unitBeats);
        std::fprintf(
          blueprintFile, "%s,%llu,%.1f,%.2f,%.2f,%u\n", name.c_str(), static_cast<unsigned long long>(totals.unitBeats),
          totals.bones / n, totals.changedExact / n, totals.changedOverTolerance / n, totals.maxChanged
        );
      }
      std::fclose(blueprintFile);
    }

    std::vector<std::uint32_t> sorted = mChangedPerBeat;
    std::sort(sorted.begin(), sorted.end());
    std::uint64_t sum = 0;
    for (const std::uint32_t value : sorted) {
      sum += value;
    }
    const double mean = sorted.empty() ? 0.0 : static_cast<double>(sum) / static_cast<double>(sorted.size());
    const std::uint32_t p95 = sorted.empty() ? 0u : sorted[static_cast<std::size_t>(0.95 * (sorted.size() - 1))];
    char text[512];
    std::snprintf(
      text, sizeof(text),
      "bones: %llu beats, %zu blueprints, changed bones (over tolerance) per beat mean %.0f p95 %u max %u; at %.0f "
      "bytes per bone delta %.1f KB/s for one full-vision view",
      static_cast<unsigned long long>(mBeats), mBlueprints.size(), mean, p95, sorted.empty() ? 0u : sorted.back(),
      kBytesPerBoneDelta, mean * kBytesPerBoneDelta * 10.0 / 1000.0
    );
    return text;
  }
} // namespace faf::headless
