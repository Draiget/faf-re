#pragma once

#include "platform/PlatformDefines.h"

#if FAFRE_PLATFORM_WINDOWS
#include <cstdint>

namespace moho
{
  /**
   * Engine addition, not in the shipped binary: counts changes of Windows' default sound output
   * (the default render endpoint for games and media changed, or the one in use was disabled or
   * removed), so `SND_RecoverOutput` can rebuild XACT on the new output. XACT 2 keeps playing
   * on the device it opened at startup; the original game kept doing that until it was
   * restarted, and went silent when that device was unplugged.
   *
   * Windows calls it on its own threads; `Changes` is read from the main thread.
   */
  class AudioOutputWatch
  {
  public:
    /** Registers with Windows' device enumerator; null (logged) when that fails. */
    static AudioOutputWatch* Start();

    /** How many output changes Windows has reported so far. */
    [[nodiscard]] virtual std::uint32_t Changes() const = 0;

  protected:
    AudioOutputWatch() = default;
    ~AudioOutputWatch() = default;
  };
} // namespace moho
#endif
