#include "headless/ReplayCommandDump.h"

#include <algorithm>
#include <cstring>
#include <functional>

// Engine addition, server mode: see ReplayCommandDump.h.

namespace faf::headless
{
  namespace
  {
    [[nodiscard]] std::uint32_t Bits(
      const float value
    ) noexcept
    {
      std::uint32_t bits = 0;
      std::memcpy(&bits, &value, sizeof(bits));
      return bits;
    }
  } // namespace

  CReplayCommandDump::CReplayCommandDump(
    const std::string& path,
    const std::int32_t army,
    const bool lockstep
  )
    : mArmy(army)
    , mLockstep(lockstep)
  {
    mFile = std::fopen(path.c_str(), "w");
    if (mFile != nullptr) {
      std::fprintf(mFile, "# %s army %d\n", lockstep ? "lockstep" : "server-mode", static_cast<int>(army));
    }
  }

  CReplayCommandDump::~CReplayCommandDump()
  {
    if (mFile != nullptr) {
      std::fclose(mFile);
    }
  }

  void CReplayCommandDump::ApplyBeat(
    const std::vector<remote::wire::SCommandDescriptor>& descriptors,
    const std::vector<std::pair<std::uint32_t, remote::wire::SCommandData>>& updates,
    const std::vector<std::uint32_t>& removals,
    const std::vector<std::uint32_t>& releases
  )
  {
    for (const remote::wire::SCommandDescriptor& descriptor : descriptors) {
      // `FindOrCreateCommandIssueHelper`: an existing helper keeps its descriptor.
      if (const auto [it, made] = mHelpers.try_emplace(descriptor.id); made) {
        it->second.descriptor = descriptor;
        it->second.generation = ++mGenerations;
      }
    }
    for (const auto& [id, data] : updates) {
      const auto found = mHelpers.find(id);
      if (found == mHelpers.end()) {
        ++mUpdatesWithoutHelper;
        continue;
      }
      found->second.data = data;
    }
    for (const std::uint32_t id : removals) {
      mRemovalsWithoutHelper += mHelpers.erase(id) == 0u ? 1u : 0u;
    }
    for (const std::uint32_t id : releases) {
      mHelpers.erase(id);
    }
  }

  std::string CReplayCommandDump::Target(
    const remote::wire::SCommandTarget& target,
    const std::string& entity
  )
  {
    char text[128];
    std::snprintf(
      text,
      sizeof(text),
      "%d,%s,%08x,%08x,%08x",
      static_cast<int>(target.type),
      entity.c_str(),
      Bits(target.position[0]),
      Bits(target.position[1]),
      Bits(target.position[2])
    );
    return text;
  }

  std::string CReplayCommandDump::Entry(
    const std::uint32_t simCommand,
    const SHelper* const helper,
    const std::string& target1,
    const std::string& target2
  )
  {
    char text[256];
    if (helper == nullptr) {
      std::snprintf(text, sizeof(text), "{%08x ?}", simCommand);
      return text;
    }
    const remote::wire::SCommandDescriptor& d = helper->descriptor;
    const remote::wire::SCommandData& v = helper->data;
    std::string out;
    std::snprintf(
      text,
      sizeof(text),
      "{%08x ty=%d t1=%s t2=%s x=%d n=%d/%d f=%u bp=%u fm=%d o=%08x,%08x,%08x,%08x s=%08x sc=%zx u=",
      simCommand,
      static_cast<int>(v.type),
      target1.c_str(),
      target2.c_str(),
      static_cast<int>(v.extra),
      static_cast<int>(v.count),
      static_cast<int>(v.maxCount),
      v.flags,
      d.blueprint,
      static_cast<int>(d.formation),
      Bits(d.origin[0]),
      Bits(d.origin[1]),
      Bits(d.origin[2]),
      Bits(d.origin[3]),
      Bits(d.scale),
      std::hash<std::string>{}(d.script)
    );
    out = text;
    for (std::size_t i = 0; i < v.units.size(); ++i) {
      out += (i == 0u ? "" : ",") + std::to_string(v.units[i]);
    }
    out += " c=";
    for (std::size_t i = 0; i < v.cells.size(); ++i) {
      out += (i == 0u ? "" : ";") + std::to_string(v.cells[i].x) + "," + std::to_string(v.cells[i].z);
    }
    out += "}";
    return out;
  }

  void CReplayCommandDump::Unit(
    const std::uint32_t beat,
    const std::uint32_t unit,
    std::string text
  )
  {
    mEntries += static_cast<std::uint64_t>(std::count(text.begin(), text.end(), '{'));
    std::size_t at = 0;
    while ((at = text.find(" ?}", at)) != std::string::npos) {
      ++mMissingEntries;
      at += 3u;
    }
    const std::uint64_t hash = std::hash<std::string>{}(text);
    mUnitSeen[unit] = beat;
    const auto [it, isNew] = mUnitHash.try_emplace(unit, hash);
    if (!isNew && it->second == hash) {
      return;
    }
    it->second = hash;
    if (mFile != nullptr) {
      std::fprintf(mFile, "%u %u %s\n", beat, unit, text.c_str());
      ++mLines;
    }
  }

  void CReplayCommandDump::EndBeat(
    const std::uint32_t beat
  )
  {
    ++mBeats;
    for (auto it = mUnitSeen.begin(); it != mUnitSeen.end();) {
      if (it->second == beat) {
        ++it;
        continue;
      }
      if (mFile != nullptr) {
        std::fprintf(mFile, "%u %u gone\n", beat, it->first);
        ++mLines;
      }
      mUnitHash.erase(it->first);
      it = mUnitSeen.erase(it);
    }
  }

  std::string CReplayCommandDump::Summary() const
  {
    char text[512];
    std::snprintf(
      text,
      sizeof(text),
      "command dump (%s, army %d): %llu beats, %llu lines, %llu queue entries over the unit-beats (%llu with no "
      "helper), %zu helpers at the end; %llu updates and %llu removals of a command with no helper",
      mLockstep ? "lockstep" : "server-mode",
      static_cast<int>(mArmy),
      static_cast<unsigned long long>(mBeats),
      static_cast<unsigned long long>(mLines),
      static_cast<unsigned long long>(mEntries),
      static_cast<unsigned long long>(mMissingEntries),
      mHelpers.size(),
      static_cast<unsigned long long>(mUpdatesWithoutHelper),
      static_cast<unsigned long long>(mRemovalsWithoutHelper)
    );
    return text;
  }
} // namespace faf::headless
