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

} // namespace moho
