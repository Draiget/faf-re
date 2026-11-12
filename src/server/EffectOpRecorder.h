#pragma once

#include <vector>

#include "moho/effects/rendering/EffectOps.h"
#include "server/EffectOpEncoder.h"

namespace faf::server
{
  /**
   * The encoder takes floats (EffectOpEncoder.h): a curve becomes its bounds (min x, min y, max x, max y) and its keys
   * (x, y, z each); a parameter beam its start, end, lifetime, width and texture scale, with its attachment, texture
   * and blend mode. `floats` holds them; `args` points into it.
   */
  void FlattenEffectOpArgs(moho::SEffectOpArgs& args, std::vector<float>& floats);

  /**
   * Plan WP9.1 step 3: the sim's effect operations into one `CEffectOpEncoder`, from whichever thread performs them
   * (a sim worker's effect tick, a Lua thread, the sim thread), behind a lock; the beat's ops are taken on the sim
   * thread with `EndBeat`. `Hook` is a `moho::EffectOpHook`: the server sets it as `gEffectOpHook`, and headless's
   * `--effect-record` calls it from its own hook. One recorder at a time is attached.
   */
  class CEffectOpRecorder
  {
  public:
    CEffectOpRecorder() = default;
    CEffectOpRecorder(const CEffectOpRecorder&) = delete;
    CEffectOpRecorder& operator=(const CEffectOpRecorder&) = delete;
    ~CEffectOpRecorder();

    /** `Hook` records into this one from now on. Doesn't touch `gEffectOpHook`. */
    void Attach();
    /** `Hook` records nothing from now on (an op already inside it finishes first). */
    void Detach();

    static void Hook(moho::EEffectOp op, const moho::SEffectOpArgs& args);

    /** The ops recorded since the last call, encoded; `ticked`: whether the sim ticked its effects in that beat. */
    [[nodiscard]] SEffectBeat EndBeat(bool ticked = true);

    /** Plan WPR.10: the id the encoder gave a live effect (`CEffectOpEncoder::IdOf`), under the recorder's lock. */
    [[nodiscard]] bool IdOf(const moho::IEffect* effect, std::uint32_t& id) const;

    /** The encoder's counts. Only once no op can arrive any more (detached), or under the caller's own ordering. */
    [[nodiscard]] const CEffectOpEncoder& Encoder() const noexcept
    {
      return mEncoder;
    }

  private:
    CEffectOpEncoder mEncoder;
  };
} // namespace faf::server
