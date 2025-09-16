// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

namespace gpg {
namespace gal {
    /**
     * VFTABLE: 0x00D43654
     * COL:  0x00E51060
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\IndexBufferD3D10.cpp
     */
    class IndexBufferD3D10 {
    public:
      /**
       * Address: 0x00901D40
       * Slot: 0
       * Demangled: sub_901D40
       */
      virtual void sub_901D40() = 0;
      /**
       * Address: 0x00901BE0
       * Slot: 1
       * Demangled: gpg::gal::IndexBufferD3D10::GetContextBuffer
       */
      virtual void GetContextBuffer() = 0;
      /**
       * Address: 0x00901E00
       * Slot: 2
       * Demangled: gpg::gal::IndexBufferD3D10::Lock
       */
      virtual void Lock() = 0;
      /**
       * Address: 0x00902020
       * Slot: 3
       * Demangled: gpg::gal::IndexBufferD3D10::Unlock
       */
      virtual void Unlock() = 0;
    };
} // namespace gal
} // namespace gpg
