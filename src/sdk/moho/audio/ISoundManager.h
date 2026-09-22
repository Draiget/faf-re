#pragma once

#include <cstdint>
#include <type_traits>

#include "gpg/core/containers/FastVector.h"
#include "moho/audio/HSound.h"
#include "moho/audio/SAudioRequest.h"
#include "moho/containers/TDatList.h"

namespace moho
{
  class Entity;
  class CSndParams;

  /**
   * VFTABLE: 0x00E359B0
   * COL:     0x00E8F368
   *
   * Five pure virtuals and a virtual destructor. The class has no data members
   * of its own, so both of its special members compile to the same one
   * instruction -- `mov [this], offset ??_7ISoundManager@Moho@@6B@` -- and the
   * binary carries two byte-different emissions of that body, 0x00760A60
   * (`__thiscall`, `this` in ECX) and 0x00760F10 (`this` in EAX, the custom
   * convention MSVC picks for a COMDAT whose call sites it has all proven). One
   * belongs to this interface's own translation unit, next to its scalar
   * deleting destructor at 0x00760A70; the other sits in `CSimSoundManager`'s,
   * next to that class's own deleting destructor at 0x00760EF0 and its
   * EAX-convention constructor at 0x00760C80.
   *
   * Which of the two is the constructor and which the destructor is not
   * decidable from the bodies, because a trivial constructor and a trivial
   * virtual destructor emit the identical instruction; the addresses are
   * recorded on the members by calling convention, since a constructor that
   * other translation units call has to keep the documented `QAE`
   * (`__thiscall`) ABI. Neither emission is reachable: every use site inlined
   * it, and the surviving COMDATs are linker baggage.
   */
  class ISoundManager
  {
  public:
    /**
     * Address: 0x00760A60 (FUN_00760A60)
     * Mangled: ??0ISoundManager@Moho@@QAE@XZ
     *
     * IDA signature:
     * void __thiscall sub_760A60(Moho::ISoundManager *this@<ecx>);
     *
     * What it does:
     * Installs the interface vtable, which is this class's entire state.
     * `CSimSoundManager`'s constructor inlines it and writes the *derived*
     * vtable straight into `[eax]` at 0x00760C83, so nothing calls this.
     */
    ISoundManager();

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 0
     */
    virtual void AddEntitySound(Entity* entity, CSndParams* params) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 1
     */
    virtual void DrainRequests(gpg::fastvector_n<SAudioRequest, 8>& outRequests) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 2
     */
    virtual TDatListItem<HSound, void>* AddLoop(HSound* sound) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 3
     */
    virtual TDatListItem<HSound, void>* StopLoop(HSound* sound) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 4
     */
    virtual void Shutdown() = 0;

    /**
     * Address: 0x00760F10 (FUN_00760F10)
     * Mangled: ??1ISoundManager@Moho@@UAE@XZ
     * Slot: 5 -- held by the compiler-generated scalar deleting destructor
     *   `??_GISoundManager@Moho@@UAEPAXI@Z` at 0x00760A70, which inlines this
     *   body rather than calling it:
     *     test byte [esp+4], 1 / mov esi, ecx
     *     mov  dword [esi], 0xE359B0        ; this destructor, inlined
     *     je   skip / push esi / call ::operator delete (0x00957A60)
     *     mov  eax, esi / ret 4
     *   Every `delete` of an `ISoundManager*` in the binary dispatches through
     *   that slot: `Sim::Setup` replacing `mSoundManager` (0x0074472D),
     *   `gpg::ReadArchive`'s owned-pointer swap lane (0x007563E3), and the
     *   reflected deconstruct callback (0x007623FF).
     *
     * IDA signature:
     * void __usercall sub_760F10(Moho::ISoundManager *this@<eax>);
     *
     * What it does:
     * Restores the interface vtable, which is all a base destructor with no
     * members has to do. `CSimSoundManager`'s destructor inlines it as the
     * closing `mov dword [esi], 0xE359B0` at 0x00761569.
     */
    virtual ~ISoundManager();
  };

  static_assert(sizeof(ISoundManager) == 0x4, "ISoundManager size must be 0x4");
  static_assert(std::is_polymorphic<ISoundManager>::value, "ISoundManager must remain polymorphic");
} // namespace moho
