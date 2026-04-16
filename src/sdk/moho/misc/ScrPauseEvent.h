#pragma once

#include <cstddef>

#include "legacy/containers/String.h"
#include "moho/app/WxRuntimeTypes.h"

namespace moho
{
  /**
   * Recovered script-pause wx event payload posted by debug hook paths.
   *
   * Layout evidence:
   * - `FUN_004B4330` initializes wxEvent lanes and stores `(string,int)` at
   *   `+0x20/+0x3C`.
   * - `FUN_004B44A0` copy-clones wxEvent lanes plus payload.
   */
  class ScrPauseEvent final : public wxEventRuntime
  {
  public:
    /**
     * Address: 0x004B4330 (FUN_004B4330, sub_4B4330)
     *
     * msvc8::string const &,int
     *
     * What it does:
     * Initializes one pause-event payload with source lane and source line.
     */
    ScrPauseEvent(const msvc8::string& sourceName, int sourceLine);

    /**
     * Address: 0x004B44A0 (FUN_004B44A0, sub_4B44A0)
     *
     * What it does:
     * Copy-constructs one pause-event payload.
     */
    ScrPauseEvent(const ScrPauseEvent& other);

    /**
       * Address: 0x004B4450 (FUN_004B4450)
     *
     * What it does:
     * Releases payload string lanes and wxEvent ref-data state.
     */
    ~ScrPauseEvent();

    /**
     * Address: 0x004B4310 (FUN_004B4310, vftable lane)
     *
     * What it does:
     * Returns class-info lane storage used by wx RTTI probes.
     */
    [[nodiscard]] void* GetClassInfo() const override;

    /**
      * Alias of FUN_004B4450 (non-canonical helper lane).
     *
     * What it does:
     * Deletes this payload object.
     */
    void DeleteObject() override;

    /**
     * Address: 0x004B43F0 (FUN_004B43F0, sub_4B43F0)
     *
     * What it does:
     * Allocates and copy-clones one pause-event payload.
     */
    [[nodiscard]] ScrPauseEvent* Clone() const override;

    [[nodiscard]] const msvc8::string& GetSourceName() const noexcept;
    [[nodiscard]] int GetSourceLine() const noexcept;

  public:
    msvc8::string mSourceName; // +0x20
    int mSourceLine;           // +0x3C
  };

  /**
   * Address: 0x00BC5F40 (FUN_00BC5F40, sub_BC5F40)
   *
   * What it does:
   * Allocates one wx event-type lane for `ScrPauseEvent`.
   */
  int register_ScrPauseEventType();

  extern int gScrPauseEventType;

  static_assert(offsetof(ScrPauseEvent, mSourceName) == 0x20, "ScrPauseEvent::mSourceName offset must be 0x20");
  static_assert(offsetof(ScrPauseEvent, mSourceLine) == 0x3C, "ScrPauseEvent::mSourceLine offset must be 0x3C");
  static_assert(sizeof(ScrPauseEvent) == 0x40, "ScrPauseEvent size must be 0x40");
} // namespace moho
