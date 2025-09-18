// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

namespace moho {
  /**
   * VFTABLE: 0x00E1B52C
   * COL:  0x00E70A38
   */
  class CAiFormationDBImpl
  {
  public:
    /**
     * Address: 0x0059C340
     * Slot: 0
     * Demangled: sub_59C340
     */
    virtual void sub_59C340() = 0;

    /**
     * Address: 0x0059C0C0
     * Slot: 1
     * Demangled: Moho::CAiFormationDBImpl::GetScriptName
     */
    virtual void GetScriptName() = 0;

    /**
     * Address: 0x0059C0F0
     * Slot: 2
     * Demangled: Moho::CAiFormationDBImpl::GetScriptIndex
     */
    virtual void GetScriptIndex() = 0;

    /**
     * Address: 0x0059C060
     * Slot: 3
     * Demangled: Moho::CAiFormationDBImpl::RemoveFormation
     */
    virtual void RemoveFormation() = 0;

    /**
     * Address: 0x0059C030
     * Slot: 4
     * Demangled: Moho::CAiFormationDBImpl::Update
     */
    virtual void Update() = 0;

    /**
     * Address: 0x0059C120
     * Slot: 5
     * Demangled: Moho::CAiFormationDBImpl::NewFormation
     */
    virtual void NewFormation() = 0;
  };
} // namespace moho
