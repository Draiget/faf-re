#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Sync.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/containers/TDatList.h"

namespace moho
{
  struct SDiskWatchEvent
  {
    msvc8::string mPath;          // +0x00
    std::int32_t mActionCode;     // +0x1C
    std::uint32_t mTimestampLow;  // +0x20
    std::uint32_t mTimestampHigh; // +0x24
  };

  class CDiskWatch;

  /**
   * Address: 0x00411320 (?FILE_Wild@Moho@@YA_NVStrArg@gpg@@0_ND@Z)
   */
  bool FILE_Wild(gpg::StrArg path, gpg::StrArg pattern, bool caseSensitive = false, char pathSeparator = '\\');

  class CDiskWatchListener
  {
  public:
    /**
     * Address: 0x00461B10 (FUN_00461B10, ??0CDiskWatchListener@Moho@@QAE@VStrArg@gpg@@@Z)
     *
     * What it does:
     * Initializes listener storage and optionally auto-registers it using a wildcard pattern.
     */
    explicit CDiskWatchListener(gpg::StrArg patterns);

    /**
     * Address: 0x00461C30 (FUN_00461C30, ??1CDiskWatchListener@Moho@@QAE@XZ)
     *
     * What it does:
     * Unregisters from the active watch, then clears pattern/event vectors.
     */
    virtual ~CDiskWatchListener();

    /**
     * Address: 0x00461DC0 (FUN_00461DC0, ?OnEvent@CDiskWatchListener@Moho@@EAEXABUSDiskWatchEvent@2@@Z)
     */
    virtual void OnEvent(const SDiskWatchEvent& event);

    /**
     * Address: 0x00461D00 (FUN_00461D00, ?FilterEvent@CDiskWatchListener@Moho@@UAE_NABUSDiskWatchEvent@2@@Z)
     */
    virtual bool FilterEvent(const SDiskWatchEvent& event);

    /**
     * Address: 0x00461DF0 (FUN_00461DF0, ?OnDiskWatchEvent@CDiskWatchListener@Moho@@UAEXABUSDiskWatchEvent@2@@Z)
     */
    virtual void OnDiskWatchEvent(const SDiskWatchEvent& event);

    /**
     * Address: 0x00461E90 (FUN_00461E90, ?AnyChangesPending@CDiskWatchListener@Moho@@QAE_NXZ)
     */
    [[nodiscard]]
    bool AnyChangesPending();

    /**
     * Address: 0x00461E00 (FUN_00461E00,
     * ?CopyAndClearPendingChanges@CDiskWatchListener@Moho@@QAE?AV?$vector@USDiskWatchEvent@Moho@@V?$allocator@USDiskWatchEvent@Moho@@@std@@@std@@XZ)
     */
    void CopyAndClearPendingChanges(msvc8::vector<SDiskWatchEvent>& outEvents);

  public:
    TDatListItem<CDiskWatchListener, void> mLink; // +0x04
    CDiskWatch* mWatch;                           // +0x0C
    msvc8::vector<SDiskWatchEvent> mEvents;       // +0x10
    msvc8::vector<msvc8::string> mPatterns;       // +0x20
  };

  class CDiskWatch
  {
  public:
    /**
     * Address: 0x004627C0 (FUN_004627C0, ??0CDiskWatch@Moho@@QAE@XZ)
     *
     * What it does:
     * Initializes watch-list sentinel links and synchronization state.
     */
    CDiskWatch();

    /**
     * Address: 0x00462870 (loc_462870, CDiskWatch cleanup helper)
     */
    ~CDiskWatch();

    /**
     * Address: 0x00462A30 (FUN_00462A30, ?AddListener@CDiskWatch@Moho@@QAEXPAVCDiskWatchListener@2@@Z)
     */
    void AddListener(CDiskWatchListener* listener);

    /**
     * Address: 0x00462A80 (FUN_00462A80, ?RemoveListener@CDiskWatch@Moho@@QAEXPAVCDiskWatchListener@2@@Z)
     */
    void RemoveListener(CDiskWatchListener* listener);

    /**
     * Address: 0x00462F80 (?EnablePrivileges@CDiskWatch@Moho@@ABE_NXZ)
     */
    [[nodiscard]]
    bool EnablePrivileges() const;

  public:
    TDatListItem<CDiskWatchListener, void> mListeners; // +0x00
    void* mUnknown08;                                  // +0x08
    gpg::core::SharedLock mLock;                       // +0x0C
    std::uint8_t mOpaque10[0x14];                      // +0x10
  };

  /**
   * Address: 0x00463310 (?DISK_AddWatchListener@Moho@@YAXPAVCDiskWatchListener@1@@Z)
   */
  void DISK_AddWatchListener(CDiskWatchListener* listener);

  /**
   * Address: 0x00463340 (?DISK_RemoveWatchListener@Moho@@YAXPAVCDiskWatchListener@1@@Z)
   */
  void DISK_RemoveWatchListener(CDiskWatchListener* listener);

  /**
   * Address: 0x004633D0 (?DISK_ResetWatch@Moho@@YAXXZ)
   */
  void DISK_ResetWatch();

  static_assert(sizeof(SDiskWatchEvent) == 0x28, "SDiskWatchEvent size must be 0x28");
  static_assert(offsetof(SDiskWatchEvent, mActionCode) == 0x1C, "SDiskWatchEvent::mActionCode offset must be 0x1C");
  static_assert(sizeof(CDiskWatchListener) == 0x30, "CDiskWatchListener size must be 0x30");
  static_assert(offsetof(CDiskWatchListener, mLink) == 0x04, "CDiskWatchListener::mLink offset must be 0x04");
  static_assert(offsetof(CDiskWatchListener, mWatch) == 0x0C, "CDiskWatchListener::mWatch offset must be 0x0C");
  static_assert(offsetof(CDiskWatchListener, mEvents) == 0x10, "CDiskWatchListener::mEvents offset must be 0x10");
  static_assert(offsetof(CDiskWatchListener, mPatterns) == 0x20, "CDiskWatchListener::mPatterns offset must be 0x20");
  static_assert(sizeof(CDiskWatch) == 0x24, "CDiskWatch size must be 0x24");
  static_assert(offsetof(CDiskWatch, mLock) == 0x0C, "CDiskWatch::mLock offset must be 0x0C");
} // namespace moho
