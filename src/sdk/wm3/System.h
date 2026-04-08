#pragma once

#include <cstddef>

namespace Wm3
{
  class System
  {
  public:
    /**
     * Address: 0x00A48F30 (FUN_00A48F30, Wm3::System::Memcpy)
     *
     * What it does:
     * Copies `sourceSize` bytes using secure memcpy semantics and returns
     * `destination` on success; returns `nullptr` on copy failure.
     */
    static void* Memcpy(
      void* destination,
      std::size_t destinationSize,
      const void* source,
      std::size_t sourceSize
    ) noexcept;
  };
} // namespace Wm3

