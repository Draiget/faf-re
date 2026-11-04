#pragma once

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <vector>

#include "gpg/core/algorithms/MD5.h"

namespace moho
{
  class Sim;

  /** One `Sim::FlattenMapRect` stamp: the clamped rect and the height written into it. */
  struct SSimFlatten
  {
    std::int32_t x0;
    std::int32_t z0;
    std::int32_t x1;
    std::int32_t z1;
    float elevation;
  };

  /**
   * Engine addition (replay keyframes), not in the binary.
   *
   * What a sim needs to continue from a keyframe and that `Sim::SaveState` leaves out. A saved game
   * restarts the beat count and the checksum, and keeps only the rects of flattened terrain (retail
   * 0x00745020): the heights come back as the map file has them. A keyframe has to continue the
   * recorded game exactly, so the header carries all of these. It goes in front of the archive.
   */
  struct SSimKeyframeHeader
  {
    std::uint32_t beat = 0; // `Sim::mCurBeat` when saved: the next beat to publish
    std::uint32_t tick = 0;
    std::int32_t pausedBy = -1;
    std::int32_t commandSource = 255;
    bool singleStep = false;
    bool gameEnded = false;
    bool gameOver = false;
    gpg::MD5Context context{};
    gpg::MD5Digest hashes[128]{};
    std::vector<std::int32_t> timeouts; // per command source
    std::vector<SSimFlatten> flattens;  // in stamping order
    // The Lua collector's counters. A collection clears weak tables such as TrashBag, and a bag with
    // a hole takes its next entry elsewhere, so the restored sim has to collect when the game did.
    std::uint64_t luaBlocks = 0;
    std::uint64_t luaThreshold = 0;
    // The free list of SimBlockLane in its order: each block's address in the saved game, and what
    // it held (kBlockBytes each). A unit's cached formation pointer can name such a block, and
    // `Unit::GetFormationVector` reads through it. Empty on x86, which has no such list.
    std::vector<std::uint64_t> laneBlocks;
    std::vector<std::uint8_t> laneBytes;
  };

  /**
   * Added to every beat number the driver dequeues to get its own count. The driver and the clients
   * count from 0 in every session; a sim restored from a keyframe keeps the recorded game's numbers.
   */
  inline std::atomic<std::int32_t> gSimBeatOrigin{0};

  /**
   * Room for a keyframe packed by `compress2`. x86 links wxWindows' older zlib, which has no
   * `compressBound` and asks for 0.1% over the size plus 12 bytes; this is above that and above 1.2.3's bound.
   */
  [[nodiscard]] constexpr unsigned long SIM_KeyframePackBound(const unsigned long size) noexcept
  {
    return size + (size >> 9) + 64u;
  }

  /** Forgets the stamps of the previous game. */
  void SIM_ResetFlattenLog();

  /** Remembers one stamp for the next keyframe's header. Sim thread. */
  void SIM_NoteFlatten(const SSimFlatten& flatten);

  /** Fills `header` from the sim, between beats, on the sim's thread. */
  void SIM_CaptureKeyframeHeader(const Sim& sim, SSimKeyframeHeader& header);

  [[nodiscard]] bool SIM_WriteKeyframeHeader(std::FILE* file, const SSimKeyframeHeader& header);
  [[nodiscard]] bool SIM_ReadKeyframeHeader(std::FILE* file, SSimKeyframeHeader& header);

  /**
   * Makes the next `Sim::Load` restore a keyframe with this header: exact archive mode (see
   * gSimExactArchive), the terrain stamps, and no post-load Lua, which would change the sim.
   */
  void SIM_BeginKeyframeRestore(SSimKeyframeHeader header);

  /**
   * While restoring: a formation, projectile or pose array now at `block` had the address `saved`
   * in the saved game. These share SimBlockLane's blocks, so a stale formation pointer can name any.
   */
  void SIM_NoteKeyframeBlock(std::uint64_t saved, void* block);

  /** While restoring: `*slot` is a cached formation pointer that held `saved` in the saved game. */
  void SIM_NoteKeyframeFormationPointer(void** slot, std::uint64_t saved);

  /**
   * After the archive: gives the cached formation pointers their new values. Two that were equal
   * stay equal, and one that names a block nothing holds now gets a block of its own.
   */
  void SIM_ResolveKeyframeFormationPointers();

  /** The header of the restore in progress, or null. */
  [[nodiscard]] const SSimKeyframeHeader* SIM_KeyframeRestore() noexcept;

  /**
   * Ends the restore, after the opening `Sim::Sync` the driver publishes. That sync closes a beat of
   * its own, so what it changes is put back here: the beat, the checksum and the hash ring. The Lua
   * collector, kept off since the load began, goes on from the keyframe's counters.
   */
  void SIM_FinishKeyframeRestore(Sim& sim);
} // namespace moho
