#include "ISoundManager.h"
#include "gpg/core/reflection/Reflection.h"

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

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<ISoundManager>`, vtable 0x00E35A40.
   *
   * Address: 0x00BDC4C0 (FUN_00BDC4C0 -- constructs the global and registers its destructor.)
   * Address: 0x00C014D0 (FUN_00C014D0 -- the global's destructor.)
   * Address: 0x00760BF0 (FUN_00760BF0 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x00761BE0 (FUN_00761BE0 -- `Init`.)
   * Address: 0x00760BD0 (FUN_00760BD0 -- `Deserialize`, `MemberDeserialize` inlined.)
   * Address: 0x00760BE0 (FUN_00760BE0 -- `Serialize`, `MemberSerialize` inlined.)
   */
  struct ISoundManagerSerializer : gpg::SerSaveLoadHelper<ISoundManager>
  {};
} // namespace moho

namespace
{
  // Address: 0x010BAE8C -- process-global `ISoundManagerSerializer` singleton.
  moho::ISoundManagerSerializer gISoundManagerSerializer;
} // namespace
