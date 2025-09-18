// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

namespace moho { class ETaskStatus; } // forward decl

namespace moho {
  /**
   * VFTABLE: 0x00E1B3AC
   * COL:  0x00E70540
   */
  class IAiCommandDispatchImpl
  {
  public:
    /**
     * Address: 0x005990F0
     * Slot: 0
     * Demangled: sub_5990F0
     */
    virtual void sub_5990F0() = 0;

    /**
     * Address: 0x00598E80
     * Slot: 1
     * Demangled: public: virtual enum Moho::ETaskStatus __thiscall Moho::IAiCommandDispatchImpl::TaskTick(void)
     */
    virtual ETaskStatus TaskTick() = 0;
  };
} // namespace moho
