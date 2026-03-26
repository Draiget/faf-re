#pragma once

#include <stdexcept>

namespace moho
{
  /**
   * VFTABLE: 0x00E0B718
   * COL: 0x00E64790
   */
  class XAudioError : public std::runtime_error
  {
  public:
    using std::runtime_error::runtime_error;

    /**
     * Address: 0x004D85D0 (FUN_004D85D0, Moho::XAudioError::dtr)
     * Slot: 0
     *
     * What it does:
     * Runs deleting-style teardown inherited from `std::runtime_error`.
     */
    ~XAudioError() override;
  };

  static_assert(sizeof(XAudioError) == sizeof(std::runtime_error), "XAudioError size must match std::runtime_error");
} // namespace moho

