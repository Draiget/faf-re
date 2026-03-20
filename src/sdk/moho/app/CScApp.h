#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/time/Timer.h"
#include "moho/app/IWinApp.h"

class CScApp final : public moho::IWinApp
{
public:
  struct RollingFrameRates
  {
    float vals[10];     // +0x00
    std::int32_t start; // +0x28
    std::int32_t end;   // +0x2C

    /**
     * Address: 0x008D5280 (FUN_008D5280, sub_8D5280)
     *
     * What it does:
     * Flushes the ring and resets start/end indexes to zero.
     */
    void Reset();

    /**
     * Address: 0x008D4B20 (FUN_008D4B20, struct_RollingFrameRates::median)
     *
     * What it does:
     * Copies the active ring window to a scratch buffer, sorts it,
     * and returns the middle sample.
     */
    [[nodiscard]]
    float Median() const;
  };
  static_assert(sizeof(RollingFrameRates) == 0x30, "CScApp::RollingFrameRates size must be 0x30");
  static_assert(offsetof(RollingFrameRates, start) == 0x28, "CScApp::RollingFrameRates::start offset must be 0x28");
  static_assert(offsetof(RollingFrameRates, end) == 0x2C, "CScApp::RollingFrameRates::end offset must be 0x2C");

  /**
   * Address: 0x008CE0A0 (FUN_008CE0A0)
   * Mangled context: constructor prologue used by app bootstrap.
   *
   * What it does:
   * Initializes core CScApp runtime fields after IWinApp base construction.
   */
  CScApp();

  /**
   * Address: 0x008D1CB0 (FUN_008D1CB0, CScApp::Dtr scalar deleting dtor)
   *
   * What it does:
   * Clears rolling framerate state, then tears down IWinApp base state.
   */
  ~CScApp() override;

  /**
   * Address: 0x008CEDE0 (FUN_008CEDE0)
   * Mangled: ?Init@CScApp@@UAE_NXZ
   *
   * What it does:
   * App-specific startup phase called from WIN_AppExecute.
   */
  bool Init() override;

  /**
   * Address: 0x008D1470 (FUN_008D1470)
   * Mangled: ?Main@CScApp@@UAEXXZ
   *
   * What it does:
   * App per-frame driver phase called from WIN_AppExecute.
   */
  void Main() override;

  /**
   * Address: 0x008D0F20 (FUN_008D0F20)
   * Mangled: ?Destroy@CScApp@@UAEXXZ
   *
   * What it does:
   * App shutdown teardown phase called from WIN_AppExecute.
   */
  void Destroy() override;

  /**
   * Address: 0x008CE1D0 (FUN_008CE1D0, CScApp::HasFrame)
   * Mangled: ?AppDoSuppressWindowsKeys@CScApp@@UBE_NXZ
   *
   * What it does:
   * Returns whether low-level keyboard suppression should be active.
   * Binary behavior requires: render device ready + windowed head + live frame.
   */
  bool AppDoSuppressWindowsKeys() const override;

public:
  // +0x40 in FA complete-object layout. Constructor leaves this slot untouched.
  std::uint32_t unknown40;
  // +0x44 (SPI_SETSCREENSAVEACTIVE value restored in Destroy).
  std::uint32_t usingScreensaver;
  // +0x48
  std::uint8_t initialized;
  // +0x49
  std::uint8_t isMinimized;
  // +0x4A..+0x4B
  std::uint8_t reserved4A[2];
  // +0x4C
  void* supcomFrame;
  // +0x50
  void* frame;
  // +0x54 (first-frame timing gate)
  std::uint8_t firstFramePending;
  // +0x55..+0x57
  std::uint8_t reserved55[3];
  // +0x58
  gpg::time::Timer curTime;
  // +0x60
  RollingFrameRates framerates;
};

static_assert(offsetof(CScApp, unknown40) == 0x40, "CScApp::unknown40 offset must be 0x40");
static_assert(offsetof(CScApp, usingScreensaver) == 0x44, "CScApp::usingScreensaver offset must be 0x44");
static_assert(offsetof(CScApp, initialized) == 0x48, "CScApp::initialized offset must be 0x48");
static_assert(offsetof(CScApp, isMinimized) == 0x49, "CScApp::isMinimized offset must be 0x49");
static_assert(offsetof(CScApp, supcomFrame) == 0x4C, "CScApp::supcomFrame offset must be 0x4C");
static_assert(offsetof(CScApp, frame) == 0x50, "CScApp::frame offset must be 0x50");
static_assert(offsetof(CScApp, firstFramePending) == 0x54, "CScApp::firstFramePending offset must be 0x54");
static_assert(offsetof(CScApp, curTime) == 0x58, "CScApp::curTime offset must be 0x58");
static_assert(offsetof(CScApp, framerates) == 0x60, "CScApp::framerates offset must be 0x60");
static_assert(sizeof(CScApp) == 0x90, "CScApp size must be 0x90");
