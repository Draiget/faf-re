#include "moho/entity/Shield.h"

#include "gpg/core/reflection/RListType.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace moho
{
  /**
   * Address: 0x00752320 (FUN_00752320, preregister_RListType_ShieldPtr)
   *
   * What it does:
   * The `list<Shield*>` reflection type, constructed on first call.
   */
  gpg::RType* preregister_RListType_ShieldPtr();
} // namespace moho

namespace
{
  struct ShieldPtrListReflectionBootstrap
  {
    ShieldPtrListReflectionBootstrap()
    {
      (void)moho::preregister_RListType_ShieldPtr();
    }
  };

  [[maybe_unused]] ShieldPtrListReflectionBootstrap gShieldPtrListReflectionBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00752320 (FUN_00752320, preregister_RListType_ShieldPtr)
   *
   * What it does:
   * Constructs the `gpg::RListType<moho::Shield*>` static (`Sim::mShields`),
   * which preregisters it for `typeid(msvc8::list<moho::Shield*>)`, and
   * returns it.
   *
   * `RListType<Shield*>`, vtable 0x00E347BC:
   *
   * Address: 0x0074CD20 (FUN_0074CD20 -- `GetName`, from `Shield::GetPointerType()`'s name.)
   * Address: 0x00C00FB0 (FUN_00C00FB0 -- the atexit destructor of `GetName`'s name string.)
   * Address: 0x0074CDC0 (FUN_0074CDC0 -- `GetLexical`; reads `_Mysize` at 0x0074CDFC with no null test.)
   * Address: 0x0074CDA0 (FUN_0074CDA0 -- `Init`.)
   * Address: 0x0074E3C0 (FUN_0074E3C0 -- `SerLoad`; each shield read by `ReadPointer<Shield>` 0x007545A0.)
   * Address: 0x0074E440 (FUN_0074E440 -- `SerSave`; each shield written `Unowned` through `MakeRRef<Shield>` 0x00753FC0, owned by `*ownerRef`.)
   */
  gpg::RType* preregister_RListType_ShieldPtr()
  {
    static gpg::RListType<moho::Shield*> typeInfo;
    return &typeInfo;
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_RListType_ShieldPtr_095a6f, moho::preregister_RListType_ShieldPtr)
