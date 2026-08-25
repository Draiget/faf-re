#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class CDecalBuffer;

  /**
   * Address: 0x0077F160 (FUN_0077F160)
   *
   * IDA signature:
   * void __usercall sub_77F160(BinaryWriteArchive *ar@<eax>, Moho::CDecalBuffer *buf@<esi>);
   *
   * What it does:
   * Save body for one `CDecalBuffer` payload: writes the owning `Sim` as an
   * unowned tracked pointer, the id-pool sub-object via reflection, then the
   * full owned decal-handle list.
   */
  void CDecalBufferSaveCallback(gpg::WriteArchive* ar, const CDecalBuffer* buf);

  /**
   * Address: 0x0077F0F0 (FUN_0077F0F0)
   *
   * IDA signature:
   * void __usercall sub_77F0F0(gpg::ReadArchive *ar@<eax>, Moho::CDecalBuffer *buf@<esi>);
   *
   * What it does:
   * Load body for one `CDecalBuffer` payload, mirroring
   * `CDecalBufferSaveCallback`: reads the owning `Sim` as a tracked pointer,
   * the id-pool sub-object through a lazily-resolved `RType`, then the owned
   * decal-handle list.
   */
  void CDecalBufferLoadCallback(gpg::ReadArchive* ar, CDecalBuffer* buf);

  /**
   * Address: 0x00779CE0 (FUN_00779CE0)
   *
   * IDA signature:
   * void __usercall sub_779CE0(Moho::CDecalBuffer *buf@<eax>, BinaryWriteArchive *ar@<ebx>);
   *
   * What it does:
   * Writes every live `CDecalHandle` in the intrusive handle list as an owned
   * tracked pointer, then a terminating null owned-pointer sentinel.
   */
  void WriteDecalHandles(const CDecalBuffer* buf, gpg::WriteArchive* ar);

  /**
   * VFTABLE: 0x00E373D8
   * COL: 0x00E91490
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='CDecalBufferSerializer@Moho'`): `FUN_00BDD880` (real,
   * `__xc_a`-reachable) vs. a dead zero-xref duplicate at `FUN_00779C50`
   * (same field writes, no `atexit` call -- confirmed via raw asm never
   * live, despite IDA's own demangler coincidentally labeling it
   * `??0CDecalBufferSerializer@Moho@@QAE@@Z`, a plausible-looking ctor
   * mangling that does NOT make it the live one). Confirmed via raw asm:
   * the real ctor default-constructs `gpg::SerHelperBase`, binds
   * `mLoadCallback`/`mSaveCallback` to `FUN_00779C30`/`FUN_00779C40`,
   * installs the `CDecalBufferSerializer` vtable, and pushes plain
   * unmangled `FUN_00C028B0` (bare unlink-then-self-link shape, matching
   * `SerHelperBase::ResetLinks()`) as its `atexit` target -- modeled by
   * the template's own real destructor, no explicit `atexit` call needed.
   * Two zero-xref duplicate emissions of that unlink logic
   * (`FUN_00779C80`, `FUN_00779CB0`, formerly
   * `UnlinkCDecalBufferSerializerHelperPrimary/Secondary`) are dead ICF
   * twins, sha256-identical to the real atexit target.
   *
   * The previous recovery modeled the whole ctor as an untraced
   * `CDecalBufferSerializerBootstrap` struct constructor -- not tied to
   * either the real or dead ctor address -- with no `atexit` registration
   * at all.
   */
  class CDecalBufferSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDD880 (FUN_00BDD880, dynamic initializer for the global
     * `CDecalBufferSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    CDecalBufferSerializer();

    /**
     * Address: 0x00C028B0 (FUN_00C028B0, Moho::CDecalBufferSerializer::~CDecalBufferSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CDecalBufferSerializer();

    /**
     * Address: 0x0077AB00 (FUN_0077AB00, gpg::SerSaveLoadHelper_CDecalBuffer::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into `CDecalBuffer` RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CDecalBufferSerializer, mLoadCallback) == 0x0C, "CDecalBufferSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CDecalBufferSerializer, mSaveCallback) == 0x10, "CDecalBufferSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CDecalBufferSerializer) == 0x14, "CDecalBufferSerializer size must be 0x14");
} // namespace moho
