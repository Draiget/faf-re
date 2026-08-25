#include "moho/render/CDecalHandleSerializer.h"

#include <cstdint>

#include "moho/render/CDecalHandle.h"

namespace
{
  // Address: 0x00BDD8E0 (FUN_00BDD8E0, register_CDecalHandleSerializer) --
  // MSVC's own compiler-generated dynamic initializer for this global runs
  // the real `gpg::SerSaveLoadHelper<CDecalHandle>` ctor (self-links into
  // `sNewHelpers`, binds `mLoadCallback`/`mSaveCallback` to the template's
  // `Deserialize`/`Serialize`, installs the vtable) and registers the real
  // mangled destructor (`??1CDecalHandleSerializer@Moho@@QAE@@Z`,
  // 0x00C02940) via `atexit`. Dead zero-xref COMDAT duplicate ctors:
  // 0x0077AB90, 0x00779FD0.
  moho::CDecalHandleSerializer gCDecalHandleSerializer;
} // namespace
