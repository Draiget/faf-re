#pragma once

#include "gpg/core/containers/String.h"
#include "legacy/containers/String.h"

namespace moho
{
  class CVirtualFileSystem
  {
  public:
    /**
     * Address: 0x004661D0 (FUN_004661D0, scalar deleting thunk)
     *
     * What it does:
     * Releases virtual file-system implementations through the abstract vtable.
     */
    virtual ~CVirtualFileSystem();

    /**
     * Address: 0x00A82547 (_purecall in base)
     *
     * What it does:
     * Reserved virtual slot in the base interface.
     */
    virtual void Reserved1() = 0;

    /**
     * Address: 0x004C0D90 (indirect slot-2 callsite from ScrDiskWatcherTask::Execute)
     *
     * What it does:
     * Resolves a source path string into a canonical virtual-file-system path.
     */
    virtual void ResolvePath(msvc8::string* outPath, gpg::StrArg sourcePath) = 0;

    /**
     * Address: 0x00A82547 (_purecall in base)
     */
    virtual void Reserved3() = 0;

    /**
     * Address: 0x00A82547 (_purecall in base)
     */
    virtual void Reserved4() = 0;

    /**
     * Address: 0x00A82547 (_purecall in base)
     */
    virtual void Reserved5() = 0;
  };
} // namespace moho
