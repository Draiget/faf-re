// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

namespace gpg {
namespace gal {
    /**
     * VFTABLE: 0x00D42DAC
     * COL:  0x00E509CC
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\IndexBufferD3D9.cpp
     */
    class IndexBufferD3D9 {
    public:
      /**
       * Address: 0x008F4D80
       * Slot: 0
       * Demangled: sub_8F4D80
       */
      virtual void sub_8F4D80() = 0;
      /**
       * Address: 0x008F4BE0
       * Slot: 1
       * Demangled: gpg::gal::IndexBufferD3D9::GetContextBuffer
       */
      virtual void GetContextBuffer() = 0;
      /**
       * Address: 0x008F4E10
       * Slot: 2
       * Demangled: gpg::gal::IndexBufferD3D9::Lock
       */
      virtual void Lock() = 0;
      /**
       * Address: 0x008F4FF0
       * Slot: 3
       * Demangled: gpg::gal::IndexBufferD3D9::Unlock
       */
      virtual void Unlock() = 0;
    };
} // namespace gal
} // namespace gpg
