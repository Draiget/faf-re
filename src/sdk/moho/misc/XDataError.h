#pragma once

#include "XException.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E07DC0
   * COL: 0x00E5E3CC
   */
  class XDataError : public XException
  {
  public:
    using XException::XException;

    /**
     * Address: 0x004B2B00 (FUN_004B2B00)
     *
     * What it does:
     * Constructs one data-error object from a message payload by initializing
     * base `XException` state and rebinding the dynamic type to `XDataError`.
     */
    explicit XDataError(const char* message);

    /**
     * Address: 0x004B2E40 (FUN_004B2E40)
     *
     * What it does:
     * Copy-constructs data-error payload and inherited exception lanes.
     */
    XDataError(const XDataError& other);

    /**
     * Address: 0x004B2B20 (FUN_004B2B20)
     *
     * What it does:
     * Destroys data-error payload and inherited exception state.
     */
    ~XDataError() noexcept override;
  };
} // namespace moho
