#pragma once

#include <cstddef>

#include "legacy/containers/String.h"

namespace gpg
{
  class WriteArchive;
}

namespace moho
{
  /**
   * Save request payload passed from `CSimDriver::Dispatch()` to request objects.
   *
   * Layout shape comes from `FUN_0073C250`.
   * Address: 0x0073C3E0 (FUN_0073C3E0 -- this struct's implicit copy constructor out of line: the flag byte, then `saveName` default-initialised (`_Myres = 15`, `_Mysize = 0`, `_Bx[0] = 0`) and `assign(src, 0, npos)` 0x004056B0; usercall this=ESI, source=EAX; zero callers, unreachable -- `CSimDriver::Dispatch` (0x0073C250) inlines the same copy from `CSimDriver+0x198`; formerly `CopyByteAndStringLane` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-30.)
   */
  struct SSaveGameDispatchData
  {
    bool useSuggestedName = false;
    msvc8::string saveName;
  };
  static_assert(
    offsetof(SSaveGameDispatchData, saveName) == 0x4, "SSaveGameDispatchData::saveName offset must be 0x4"
  );
  static_assert(sizeof(SSaveGameDispatchData) == 0x20, "SSaveGameDispatchData size must be 0x20");

  /**
   * Address context:
   * - vftable 0x00E49CA8 (`Moho::ISaveRequest::vftable`)
   *
   * What it does:
   * Defines the save-request archive/finalize contract consumed by sim driver.
   */
  class ISaveRequest
  {
  public:
    /**
     * Address: 0x00A82547 (_purecall slot in base interface)
     */
    virtual gpg::WriteArchive* GetArchive() = 0;

    /**
     * Address: 0x00A82547 (_purecall slot in base interface)
     */
    virtual void Save(const SSaveGameDispatchData& data) = 0;

  protected:
    /**
     * Address: 0x0087FCE0 (FUN_0087FCE0, ??0ISaveRequest@Moho@@QAE@XZ)
     * Address: 0x00881390 (FUN_00881390, ISaveRequest ctor lane)
     *
     * What it does:
     * Initializes one save-request base interface object.
     */
    ISaveRequest();

    ~ISaveRequest() = default;
  };

  static_assert(sizeof(ISaveRequest) == 0x4, "ISaveRequest size must be 0x4");
} // namespace moho
