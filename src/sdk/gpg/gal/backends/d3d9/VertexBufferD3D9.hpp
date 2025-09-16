// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

namespace gpg {
namespace gal {
    /**
     * VFTABLE: 0x00D42F1C
     * COL:  0x00E50B04
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\VertexBufferD3D9.cpp
     */
    class VertexBufferD3D9 {
    public:
      /**
       * Address: 0x008F58C0
       * Slot: 0
       * Demangled: sub_8F58C0
       */
      virtual void sub_8F58C0() = 0;
      /**
       * Address: 0x008F5700
       * Slot: 1
       * Demangled: sub_8F5700
       */
      virtual void sub_8F5700() = 0;
      /**
       * Address: 0x008F5950
       * Slot: 2
       * Demangled: gpg::gal::VertexBufferD3D9::Lock
       */
      virtual void Lock() = 0;
      /**
       * Address: 0x008F5B40
       * Slot: 3
       * Demangled: gpg::gal::VertexBufferD3D9::Unlock
       */
      virtual void Unlock() = 0;
    };
} // namespace gal
} // namespace gpg
