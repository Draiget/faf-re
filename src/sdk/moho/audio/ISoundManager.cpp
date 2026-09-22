#include "ISoundManager.h"

namespace moho
{
  /**
   * Address: 0x00760A60 (FUN_00760A60)
   *
   * What it does:
   * `mov dword [ecx], 0xE359B0 / ret` -- the implicit default constructor of a
   * class whose only state is its vptr. Defined out of line so the emission
   * the binary carries has somewhere to live.
   */
  ISoundManager::ISoundManager() = default;

  /**
   * Address: 0x00760F10 (FUN_00760F10)
   *
   * What it does:
   * `mov dword [eax], 0xE359B0 / ret` -- the destructor body proper. The
   * deleting half (the `flags & 1` test and the `::operator delete` call at
   * 0x00760A70) is the compiler-generated `??_G` thunk that occupies vtable
   * slot 5; MSVC emits it from this declaration and it is not source.
   */
  ISoundManager::~ISoundManager() = default;
} // namespace moho
