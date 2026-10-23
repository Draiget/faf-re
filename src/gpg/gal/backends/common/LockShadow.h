#pragma once

// FAF addition, not in the shipped binary: the CPU copy that the Direct3D 11,
// Direct3D 12 and Vulkan backends hand out when the engine locks a vertex or
// index buffer.

#include <cstdint>
#include <vector>

namespace gpg::gal::backend
{
  /**
   * The bytes a buffer `Lock` returns, plus a guard band past the end.
   *
   * Direct3D 9 hands the engine driver memory, so a write past the end of a
   * locked range lands in memory the driver owns and goes unnoticed. These
   * backends hand out a heap block instead, and the same write would corrupt
   * whatever the heap put next to it - the engine then dies much later in
   * unrelated code (a log line's string, a vertex sheet's vtable). So:
   *
   *  - a lock whose range runs past the buffer's end grows the copy to cover
   *    the whole range, and is logged; the part past the end is never uploaded;
   *  - the guard band after the locked bytes is checked on unlock, and a write
   *    into it is logged and the band re-armed.
   *
   * With FAF_GAL_LOCK_BREAK=1 either event also breaks into the debugger, which
   * then shows the engine code that did it.
   */
  class LockShadow
  {
  public:
    LockShadow() = default;
    ~LockShadow();
    LockShadow(const LockShadow&) = delete;
    LockShadow& operator=(const LockShadow&) = delete;

    /** Bytes held by every LockShadow in the process (memory diagnostics). */
    [[nodiscard]] static std::uint64_t TotalBytes() noexcept;

    /** Sizes the copy for `byteWidth` bytes, zeroed, and arms the guard. */
    void Reset(std::uint32_t byteWidth);

    /**
     * The address a lock of `size` bytes at `offset` returns (`size` 0 locks
     * to the end). `kind` names the buffer in the log.
     */
    [[nodiscard]] std::uint8_t* Map(std::uint32_t offset, std::uint32_t size, const char* kind);

    /** Checks the guard band after the range the last `Map` returned. */
    void CheckGuard(const char* kind);

    [[nodiscard]] std::uint8_t* data() noexcept { return mBytes.data(); }
    [[nodiscard]] const std::uint8_t* data() const noexcept { return mBytes.data(); }

  private:
    void Arm(std::size_t from);
    void Account(std::size_t previousCapacity) noexcept;

    std::vector<std::uint8_t> mBytes;
    std::uint32_t mByteWidth = 0;
    std::uint32_t mMappedEnd = 0;    // the end of the range the last Map returned
    std::size_t mGuardStart = 0;     // where the armed band starts
  };
} // namespace gpg::gal::backend
