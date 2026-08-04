#pragma once

#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/gal/OutputContext.hpp"

namespace gpg::gal
{
  class Device;
  class DeviceContext;
  class Effect;
  class CursorContext;
  class EffectContext;
  class Head;

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
     * Address: 0x008E6700 (FUN_008E6700, func_DeivceD3DDtr)
     *
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
     * Slot: 0 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Tears the backend device down. MSVC puts the scalar deleting destructor
     * in slot 0, which is what `DestroyInstance` dispatches through.
     */
    virtual void DestroyBackendObject() = 0;
    /**
     * Slot: 1 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Returns the backend's log sink.
     */
    virtual void* GetLog() = 0;
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
     * Slot: 3 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Returns the thread id the device was created on.
     */
    virtual int GetCurThreadId() = 0;
    /**
     * Slot: 4 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Per-call pre-hook every backend entry point runs first.
     */
    virtual void Func1() = 0;
    /**
     * Address: 0x00A82547
     * Slot: 5
     * Demangled: _purecall
     */
    virtual void purecall5() {}
    /**
     * Slot: 6 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Returns one head descriptor by index.
     */
    virtual Head* GetHead1(unsigned int headIndex) = 0;
    /**
     * Slot: 7 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Returns one head output context by index.
     */
    virtual Head* GetHead2(unsigned int headIndex) = 0;
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
     *
     * What it does:
     * Creates one backend effect from `context` and hands it back through
     * `outEffect`. Pure in the binary - only a backend ever answers it - but
     * carried here with a body so `Device` stays instantiable like its 45
     * siblings.
     *
     * The signature has to live on the base. It used to be declared
     * `purecall9()` with no arguments, which meant DeviceD3D9::CreateEffect
     * did not override it - C++ appended the backend's method as a new slot
     * past the base's, so slot 9 still held this stub. Effect::Create pushes
     * two arguments and expects a __thiscall callee to pop 8; the stub popped
     * 0, and the debug CRT's _RTC_CheckEsp trapped the moment the first
     * effect was compiled.
     */
    virtual boost::shared_ptr<Effect>* CreateEffect(
      boost::shared_ptr<Effect>* outEffect,
      EffectContext* context
    );
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
     * Slot: 25 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Backend state query.
     */
    virtual int Func8() = 0;
    /**
     * Slot: 26 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Rebinds the device to one context.
     */
    virtual int Func9(DeviceContext* context) = 0;
    /**
     * Slot: 27 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Reports whether the device is usable, lost, or needs a reset.
     */
    virtual int TestCooperativeLevel() = 0;
    /**
     * Slot: 28 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Opens a scene.
     */
    virtual int BeginScene() = 0;
    /**
     * Slot: 29 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Closes the open scene.
     */
    virtual void EndScene() = 0;
    /**
     * Slot: 30 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Presents the back buffer.
     */
    virtual void Present() = 0;
    /**
     * Slot: 31 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Uploads the hardware cursor image.
     */
    virtual void SetCursor(const CursorContext* context) = 0;
    /**
     * Address: 0x00A82547
     * Slot: 32
     * Demangled: _purecall
     */
    virtual void purecall32() {}
    /**
     * Slot: 33 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Shows or hides the hardware cursor.
     */
    virtual int ShowCursor(bool show) = 0;
    /**
     * Slot: 34 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Binds one viewport rectangle.
     */
    virtual void SetViewport(const void* viewport) = 0;
    /**
     * Slot: 35 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Reads the bound viewport rectangle.
     */
    virtual void GetViewport(void* outViewport) = 0;

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
     * Slot: 38 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Clears the bound target, depth and stencil.
     */
    virtual void Clear(
        bool clearTarget,
        bool clearZbuffer,
        bool clearStencil,
        std::uint32_t color,
        float depth,
        int stencil
    ) = 0;
    /**
     * Slot: 39 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Unbinds every texture stage.
     */
    virtual int ClearTextures() = 0;
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
     * Slot: 43 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Sets the fixed-function fog parameters.
     */
    virtual void SetFogState(
        bool enable,
        const void* projection,
        float fogStart,
        float fogEnd,
        int fogColor
    ) = 0;
    /**
     * Slot: 44 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Switches between filled and wireframe fill mode.
     */
    virtual int SetWireframeState(bool enabled) = 0;
    /**
     * Slot: 45 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Sets the colour-write mask.
     */
    virtual int SetColorWriteState(bool arg1, bool arg2) = 0;
    /**
     * Slot: 46 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Issues one indexed draw.
     */
    virtual int DrawIndexedPrimitive(const void* context) = 0;
    /**
     * Slot: 47 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Issues one non-indexed draw.
     */
    virtual int DrawPrimitive(const void* context) = 0;
    /**
     * Slot: 48 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Begins the selected effect technique.
     */
    virtual void BeginTechnique() = 0;
    /**
     * Slot: 49 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Ends the active effect technique.
     */
    virtual void EndTechnique() = 0;

  protected:
    std::uint32_t reserved0x04_ = 0; // +0x04
    OutputContext outputContext_{};  // +0x08
  };
} // namespace gpg::gal

