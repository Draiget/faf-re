// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include <cstddef>
#include <cstdint>

namespace gpg
{
  namespace gal
  {
    /**
     * VFTABLE: 0x00D449A4
     * COL:  0x00E51238
     */
    class VertexFormat
    {
    public:
      /**
       * Address: 0x009044C0 (FUN_009044C0, gpg::gal::VertexFormat::VertexFormat)
       *
       * What it does:
       * Restores base vertex-format vtable ownership and clears three runtime
       * state lanes used by derived backend wrappers.
       */
      VertexFormat();

      /**
       * Address: 0x00A82547
       * Slot: 0
       * Demangled: _purecall
       */
      virtual void purecall0() = 0;

    public:
      std::uint8_t mReserved04[0x08]; // +0x04
      std::uint32_t mState0C; // +0x0C
      std::uint32_t mState10; // +0x10
      std::uint32_t mState14; // +0x14
    };

    static_assert(offsetof(VertexFormat, mReserved04) == 0x04, "VertexFormat::mReserved04 offset must be 0x04");
    static_assert(offsetof(VertexFormat, mState0C) == 0x0C, "VertexFormat::mState0C offset must be 0x0C");
    static_assert(offsetof(VertexFormat, mState10) == 0x10, "VertexFormat::mState10 offset must be 0x10");
    static_assert(offsetof(VertexFormat, mState14) == 0x14, "VertexFormat::mState14 offset must be 0x14");
  } // namespace gal
} // namespace gpg
