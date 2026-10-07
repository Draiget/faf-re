#pragma once

#include <cstdint>

namespace moho::cri
{
  /**
   * The one signed word the CRI Sofdec/ADX middleware passes addresses
   * through. Object handles (`Hn`), conditions (`SFD_SetCond`), error and
   * server callbacks (`MPV_SetErrFunc`, `ADXM` decode-server slots),
   * heap-manager references and stream-journal buffer addresses (`Sj`) all
   * travel as this word between the mw libraries.
   *
   * The 2007 middleware was 32-bit and the word was a plain `int`. On 64-bit
   * builds the same slots must carry full pointers, so the word is
   * pointer-wide there; on 32-bit builds `std::intptr_t` is exactly the
   * original 32-bit `int`, so the recovered ABI and behaviour are unchanged.
   */
  using SofdecAddressWord = std::intptr_t;
}

/**
 * Global-spelling alias: the middleware's libraries are C and their recovered
 * declarations sit at global scope, where the qualified name would be noise.
 * It is the same type as `moho::cri::SofdecAddressWord`.
 */
using SofdecAddressWord = moho::cri::SofdecAddressWord;
