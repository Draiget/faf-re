#pragma once

#include <cstdint>

#include "gpg/gal/OutputContext.hpp"

namespace gpg::gal
{
  class Device;
  class DeviceContext;

  /**
   * Address: 0x0079CB10 (FUN_0079CB10, gpg::gal::WindowIsForeground)
   *
   * What it does:
   * Returns true when the OS foreground HWND matches any active GAL device
   * head window/handle lane.
   */
  [[nodiscard]] bool WindowIsForeground();

  /**
   * VFTABLE: 0x00D42224
   * COL:     0x00E5050C
   */
  class Device
  {
  public:
    /**
     * Address: 0x008E6730 (FUN_008E6730)
     *
     * What it does:
     * Returns the global active device singleton pointer.
     */
    static Device* GetInstance();

    /**
     * Address family:
     * - used by 0x0042EA00 (FUN_0042EA00)
     * - used by 0x0042EA30 (FUN_0042EA30)
     * - used by 0x0042EAE0 (FUN_0042EAE0)
     *
     * What it does:
     * Returns true when the global active device singleton is available.
     */
    static bool IsReady();

    /**
     * What it does:
     * Replaces the global active device singleton pointer.
     */
    static void SetInstance(Device* device);

    /**
     * What it does:
     * Destroys and clears the global active device singleton when present.
     */
    static void DestroyInstance();

    /**
     * Address: 0x0042EAE0 (FUN_0042EAE0)
     *
     * What it does:
     * Forwards one cursor initialization request to the active backend device.
     */
    static void InitCursor();

    /**
     * Address: 0x00A82547
     * Slot: 0
     * Demangled: _purecall
     */
    virtual void purecall0() {}
    /**
     * Address: 0x00A82547
     * Slot: 1
     * Demangled: _purecall
     */
    virtual void purecall1() {}
    /**
     * Address context:
     * - 0x008D0E7C callsite in `CScApp::CreateDevice` (`FUN_008D0370`)
     *   dispatches slot-2 and ignores return value.
     *
     * What it does:
     * Returns the active device-context object for the backend device.
     */
    virtual DeviceContext* GetDeviceContext() { return nullptr; }
    /**
     * Address: 0x00A82547
     * Slot: 3
     * Demangled: _purecall
     */
    virtual void purecall3() {}
    /**
     * Address: 0x00A82547
     * Slot: 4
     * Demangled: _purecall
     */
    virtual void purecall4() {}
    /**
     * Address: 0x00A82547
     * Slot: 5
     * Demangled: _purecall
     */
    virtual void purecall5() {}
    /**
     * Address: 0x00A82547
     * Slot: 6
     * Demangled: _purecall
     */
    virtual void purecall6() {}
    /**
     * Address: 0x00A82547
     * Slot: 7
     * Demangled: _purecall
     */
    virtual void purecall7() {}
    /**
     * Address: 0x00A82547
     * Slot: 8
     * Demangled: _purecall
     */
    virtual void purecall8() {}
    /**
     * Address: 0x00A82547
     * Slot: 9
     * Demangled: _purecall
     */
    virtual void purecall9() {}
    /**
     * Address: 0x00A82547
     * Slot: 10
     * Demangled: _purecall
     */
    virtual void purecall10() {}
    /**
     * Address: 0x00A82547
     * Slot: 11
     * Demangled: _purecall
     */
    virtual void purecall11() {}
    /**
     * Address: 0x00A82547
     * Slot: 12
     * Demangled: _purecall
     */
    virtual void purecall12() {}
    /**
     * Address: 0x00A82547
     * Slot: 13
     * Demangled: _purecall
     */
    virtual void purecall13() {}
    /**
     * Address: 0x00A82547
     * Slot: 14
     * Demangled: _purecall
     */
    virtual void purecall14() {}
    /**
     * Address: 0x00A82547
     * Slot: 15
     * Demangled: _purecall
     */
    virtual void purecall15() {}
    /**
     * Address: 0x00A82547
     * Slot: 16
     * Demangled: _purecall
     */
    virtual void purecall16() {}
    /**
     * Address: 0x00A82547
     * Slot: 17
     * Demangled: _purecall
     */
    virtual void purecall17() {}
    /**
     * Address: 0x00A82547
     * Slot: 18
     * Demangled: _purecall
     */
    virtual void purecall18() {}
    /**
     * Address: 0x00A82547
     * Slot: 19
     * Demangled: _purecall
     */
    virtual void purecall19() {}
    /**
     * Address: 0x00A82547
     * Slot: 20
     * Demangled: _purecall
     */
    virtual void purecall20() {}
    /**
     * Address: 0x00A82547
     * Slot: 21
     * Demangled: _purecall
     */
    virtual void purecall21() {}
    /**
     * Address: 0x00A82547
     * Slot: 22
     * Demangled: _purecall
     */
    virtual void purecall22() {}
    /**
     * Address: 0x00A82547
     * Slot: 23
     * Demangled: _purecall
     */
    virtual void purecall23() {}
    /**
     * Address: 0x00A82547
     * Slot: 24
     * Demangled: _purecall
     */
    virtual void purecall24() {}
    /**
     * Address: 0x00A82547
     * Slot: 25
     * Demangled: _purecall
     */
    virtual void purecall25() {}
    /**
     * Address: 0x00A82547
     * Slot: 26
     * Demangled: _purecall
     */
    virtual void purecall26() {}
    /**
     * Address: 0x00A82547
     * Slot: 27
     * Demangled: _purecall
     */
    virtual void purecall27() {}
    /**
     * Address: 0x00A82547
     * Slot: 28
     * Demangled: _purecall
     */
    virtual void purecall28() {}
    /**
     * Address: 0x00A82547
     * Slot: 29
     * Demangled: _purecall
     */
    virtual void purecal29l() {}
    /**
     * Address: 0x00A82547
     * Slot: 30
     * Demangled: _purecall
     */
    virtual void purecall30() {}
    /**
     * Address: 0x00A82547
     * Slot: 31
     * Demangled: _purecall
     */
    virtual void purecall31() {}
    /**
     * Address: 0x00A82547
     * Slot: 32
     * Demangled: _purecall
     */
    virtual void purecall32() {}
    /**
     * Address: 0x00A82547
     * Slot: 33
     * Demangled: _purecall
     */
    virtual void purecall33() {}
    /**
     * Address: 0x00A82547
     * Slot: 34
     * Demangled: _purecall
     */
    virtual void purecall34() {}
    /**
     * Address: 0x00A82547
     * Slot: 35
     * Demangled: _purecall
     */
    virtual void purecall35() {}

    /**
     * Address: 0x008E6940 (FUN_008E6940)
     *
     * OutputContext const *
     *
     * What it does:
     * Copies the caller-provided output-target context into the device's active output context.
     */
    virtual void ClearTarget(const OutputContext* context);

    /**
     * Address: 0x008E6810 (FUN_008E6810)
     *
     * OutputContext *
     *
     * What it does:
     * Writes the device's active output-target context to the caller-provided context object.
     */
    virtual void GetContext(OutputContext* outContext);

    /**
     * Address: 0x00A82547
     * Slot: 38
     * Demangled: _purecall
     */
    virtual void purecall38() {}
    /**
     * Address: 0x00A82547
     * Slot: 39
     * Demangled: _purecall
     */
    virtual void purecall39() {}
    /**
     * Address: 0x00A82547
     * Slot: 40
     * Demangled: _purecall
     */
    virtual void purecall40() {}
    /**
     * Address: 0x00A82547
     * Slot: 41
     * Demangled: _purecall
     */
    virtual void purecall41() {}
    /**
     * Address: 0x00A82547
     * Slot: 42
     * Demangled: _purecall
     */
    virtual void purecall42() {}
    /**
     * Address: 0x00A82547
     * Slot: 43
     * Demangled: _purecall
     */
    virtual void purecall43() {}
    /**
     * Address: 0x00A82547
     * Slot: 44
     * Demangled: _purecall
     */
    virtual void purecall44() {}
    /**
     * Address: 0x00A82547
     * Slot: 45
     * Demangled: _purecall
     */
    virtual void purecall45() {}
    /**
     * Address: 0x00A82547
     * Slot: 46
     * Demangled: _purecall
     */
    virtual void purecall46() {}
    /**
     * Address: 0x00A82547
     * Slot: 47
     * Demangled: _purecall
     */
    virtual void purecall47() {}
    /**
     * Address: 0x00A82547
     * Slot: 48
     * Demangled: _purecall
     */
    virtual void purecall48() {}
    /**
     * Address: 0x00A82547
     * Slot: 49
     * Demangled: _purecall
     */
    virtual void purecall49() {}

  protected:
    std::uint32_t reserved0x04_ = 0; // +0x04
    OutputContext outputContext_{};  // +0x08
  };
} // namespace gpg::gal

