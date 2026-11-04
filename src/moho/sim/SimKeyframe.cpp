#include "moho/sim/SimKeyframe.h"

#include <algorithm>
#include <cstring>
#include <memory>
#include <new>
#include <unordered_map>
#include <utility>

#include "lua/LuaObject.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimArchiveMode.h"
#include "moho/sim/SimBlockLane.h"

namespace moho
{
  namespace
  {
    constexpr std::uint32_t kHeaderMagic = 0x4B465246u; // "FRFK"
    constexpr std::uint32_t kHeaderVersion = 4u;

    // A keyframe's header is read from a file; a length past this is not one.
    constexpr std::uint32_t kMaxListLength = 64u * 1024u * 1024u;

    std::vector<SSimFlatten> sFlattenLog;
    std::unique_ptr<SSimKeyframeHeader> sRestore;

    struct SFormationPointer
    {
      void** slot;
      std::uint64_t saved;
    };

    std::unordered_map<std::uint64_t, void*> sRestoredBlocks;
    std::vector<SFormationPointer> sRestoredFormationPointers;

    constexpr std::size_t kUnheldBlockBytes = 2048u;

#if defined(_M_X64) || defined(__x86_64__)
    static_assert(kUnheldBlockBytes == SimBlockLane::kBlockBytes);

    // A block's first word is a vtable when it held an object. The save and the restore run the same
    // build, at another load address; this anchor turns such a word into an offset and back.
    const char kImageAnchor = 0;
    constexpr std::int64_t kImageReach = std::int64_t{1} << 30;
    constexpr std::uint64_t kImageRelative = std::uint64_t{0xFAF0} << 48;

    [[nodiscard]] std::uint64_t PackFirstWord(const std::uint64_t word) noexcept
    {
      const std::int64_t offset = static_cast<std::int64_t>(word - reinterpret_cast<std::uintptr_t>(&kImageAnchor));
      if (offset <= -kImageReach || offset >= kImageReach) {
        return word;
      }
      return kImageRelative | (static_cast<std::uint64_t>(offset + kImageReach));
    }

    [[nodiscard]] std::uint64_t UnpackFirstWord(const std::uint64_t word) noexcept
    {
      if ((word & (std::uint64_t{0xFFFF} << 48)) != kImageRelative) {
        return word;
      }
      const std::int64_t offset = static_cast<std::int64_t>(word & ~(std::uint64_t{0xFFFF} << 48)) - kImageReach;
      return reinterpret_cast<std::uintptr_t>(&kImageAnchor) + static_cast<std::uint64_t>(offset);
    }
#endif

    template <typename T>
    [[nodiscard]] bool WriteValue(std::FILE* const file, const T& value)
    {
      return std::fwrite(&value, sizeof(T), 1u, file) == 1u;
    }

    template <typename T>
    [[nodiscard]] bool ReadValue(std::FILE* const file, T& value)
    {
      return std::fread(&value, sizeof(T), 1u, file) == 1u;
    }

    template <typename T>
    [[nodiscard]] bool WriteList(std::FILE* const file, const std::vector<T>& list)
    {
      const auto count = static_cast<std::uint32_t>(list.size());
      return WriteValue(file, count) && (list.empty() || std::fwrite(list.data(), sizeof(T), list.size(), file) == list.size());
    }

    template <typename T>
    [[nodiscard]] bool ReadList(std::FILE* const file, std::vector<T>& list)
    {
      std::uint32_t count = 0;
      if (!ReadValue(file, count) || count > kMaxListLength) {
        return false;
      }
      list.resize(count);
      return list.empty() || std::fread(list.data(), sizeof(T), list.size(), file) == list.size();
    }
  } // namespace

  void SIM_ResetFlattenLog()
  {
    sFlattenLog.clear();
  }

  void SIM_NoteFlatten(const SSimFlatten& flatten)
  {
    sFlattenLog.push_back(flatten);
  }

  void SIM_CaptureKeyframeHeader(const Sim& sim, SSimKeyframeHeader& header)
  {
    header.beat = sim.mCurBeat;
    header.tick = sim.mCurTick;
    header.pausedBy = sim.mPausedByCommandSource;
    header.commandSource = sim.mCurCommandSource;
    header.singleStep = sim.mSingleStep;
    header.gameEnded = sim.mGameEnded;
    header.gameOver = sim.mGameOver;
    header.context = sim.mContext;
    std::copy(std::begin(sim.mSimHashes), std::end(sim.mSimHashes), std::begin(header.hashes));

    header.timeouts.clear();
    for (const SSTICommandSource& source : sim.mCommandSources) {
      header.timeouts.push_back(source.mTimeouts);
    }
    header.flattens = sFlattenLog;

    const global_State* const lua = sim.mLuaState->m_state->l_G;
    header.luaBlocks = lua->nblocks;
    header.luaThreshold = lua->GCthreshold;

    header.laneBlocks.clear();
    header.laneBytes.clear();
#if defined(_M_X64) || defined(__x86_64__)
    const std::vector<void*>& freeBlocks = SimBlockLane::FreeBlocks();
    header.laneBytes.resize(freeBlocks.size() * SimBlockLane::kBlockBytes);
    std::uint8_t* out = header.laneBytes.data();
    for (void* const block : freeBlocks) {
      header.laneBlocks.push_back(reinterpret_cast<std::uintptr_t>(block));
      std::memcpy(out, block, SimBlockLane::kBlockBytes);
      std::uint64_t firstWord = 0;
      std::memcpy(&firstWord, out, sizeof(firstWord));
      firstWord = PackFirstWord(firstWord);
      std::memcpy(out, &firstWord, sizeof(firstWord));
      out += SimBlockLane::kBlockBytes;
    }
#endif
  }

  bool SIM_WriteKeyframeHeader(std::FILE* const file, const SSimKeyframeHeader& header)
  {
    const std::uint8_t flags[3] = {
      static_cast<std::uint8_t>(header.singleStep),
      static_cast<std::uint8_t>(header.gameEnded),
      static_cast<std::uint8_t>(header.gameOver),
    };
    return WriteValue(file, kHeaderMagic) && WriteValue(file, kHeaderVersion) && WriteValue(file, header.beat)
      && WriteValue(file, header.tick) && WriteValue(file, header.pausedBy) && WriteValue(file, header.commandSource)
      && WriteValue(file, flags) && WriteValue(file, header.context) && WriteValue(file, header.hashes)
      && WriteList(file, header.timeouts) && WriteList(file, header.flattens) && WriteValue(file, header.luaBlocks)
      && WriteValue(file, header.luaThreshold) && WriteList(file, header.laneBlocks)
      && WriteList(file, header.laneBytes);
  }

  bool SIM_ReadKeyframeHeader(std::FILE* const file, SSimKeyframeHeader& header)
  {
    std::uint32_t magic = 0;
    std::uint32_t version = 0;
    std::uint8_t flags[3]{};
    if (!ReadValue(file, magic) || magic != kHeaderMagic || !ReadValue(file, version) || version != kHeaderVersion
        || !ReadValue(file, header.beat) || !ReadValue(file, header.tick) || !ReadValue(file, header.pausedBy)
        || !ReadValue(file, header.commandSource) || !ReadValue(file, flags) || !ReadValue(file, header.context)
        || !ReadValue(file, header.hashes) || !ReadList(file, header.timeouts) || !ReadList(file, header.flattens)
        || !ReadValue(file, header.luaBlocks) || !ReadValue(file, header.luaThreshold)
        || !ReadList(file, header.laneBlocks) || !ReadList(file, header.laneBytes)) {
      return false;
    }
    header.singleStep = flags[0] != 0u;
    header.gameEnded = flags[1] != 0u;
    header.gameOver = flags[2] != 0u;
    return header.beat > 0u;
  }

  void SIM_BeginKeyframeRestore(SSimKeyframeHeader header)
  {
    gSimBeatOrigin.store(static_cast<std::int32_t>(header.beat) - 1);

    sRestoredBlocks.clear();
    sRestoredFormationPointers.clear();
#if defined(_M_X64) || defined(__x86_64__)
    std::vector<void*> freeBlocks;
    freeBlocks.reserve(header.laneBlocks.size());
    const std::uint8_t* in = header.laneBytes.data();
    if (header.laneBytes.size() == header.laneBlocks.size() * SimBlockLane::kBlockBytes) {
      for (const std::uint64_t saved : header.laneBlocks) {
        void* const block = ::operator new(SimBlockLane::kBlockBytes);
        std::memcpy(block, in, SimBlockLane::kBlockBytes);
        std::uint64_t firstWord = 0;
        std::memcpy(&firstWord, in, sizeof(firstWord));
        firstWord = UnpackFirstWord(firstWord);
        std::memcpy(block, &firstWord, sizeof(firstWord));
        in += SimBlockLane::kBlockBytes;
        sRestoredBlocks[saved] = block;
        freeBlocks.push_back(block);
      }
    }
    SimBlockLane::SetFreeBlocks(std::move(freeBlocks));
#endif
    header.laneBlocks.clear();
    header.laneBytes.clear();

    sRestore = std::make_unique<SSimKeyframeHeader>(std::move(header));
    gSimExactArchive.store(true);
    gSimKeyframeRestoring.store(true);
  }

  void SIM_NoteKeyframeBlock(const std::uint64_t saved, void* const block)
  {
    sRestoredBlocks[saved] = block;
  }

  void SIM_NoteKeyframeFormationPointer(void** const slot, const std::uint64_t saved)
  {
    sRestoredFormationPointers.push_back(SFormationPointer{slot, saved});
  }

  void SIM_ResolveKeyframeFormationPointers()
  {
    for (const SFormationPointer& pointer : sRestoredFormationPointers) {
      if (pointer.saved == 0u) {
        *pointer.slot = nullptr;
        continue;
      }
      void*& block = sRestoredBlocks[pointer.saved];
      if (block == nullptr) {
        // The block went back to the general allocator in the saved game. `Unit::GetFormationVector`
        // reads through this pointer too, so it gets a whole block, with nothing in it.
        block = ::operator new(kUnheldBlockBytes);
        std::memset(block, 0, kUnheldBlockBytes);
      }
      *pointer.slot = block;
    }
    sRestoredFormationPointers.clear();
    sRestoredBlocks.clear();
  }

  const SSimKeyframeHeader* SIM_KeyframeRestore() noexcept
  {
    return sRestore.get();
  }

  void SIM_FinishKeyframeRestore(Sim& sim)
  {
    gSimExactArchive.store(false);
    gSimKeyframeRestoring.store(false);

    const SSimKeyframeHeader& header = *sRestore;
    sim.mCurBeat = header.beat;
    sim.mPausedByCommandSource = header.pausedBy;
    sim.mCurCommandSource = header.commandSource;
    sim.mSingleStep = header.singleStep;
    sim.mGameEnded = header.gameEnded;
    sim.mGameOver = header.gameOver;
    sim.mContext = header.context;
    std::copy(std::begin(header.hashes), std::end(header.hashes), std::begin(sim.mSimHashes));

    const std::size_t sources = std::min(header.timeouts.size(), static_cast<std::size_t>(sim.mCommandSources.size()));
    for (std::size_t index = 0; index < sources; ++index) {
      sim.mCommandSources[index].mTimeouts = header.timeouts[index];
    }

    global_State* const lua = sim.mLuaState->m_state->l_G;
    lua->nblocks = static_cast<lu_mem>(header.luaBlocks);
    lua->GCthreshold = static_cast<lu_mem>(header.luaThreshold);

    sFlattenLog = header.flattens;
    sRestore.reset();
  }
} // namespace moho
