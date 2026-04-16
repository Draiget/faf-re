#include "moho/ai/IAiSiloBuild.h"

#include <new>

#include "moho/ai/CAiSiloBuildImpl.h"

using namespace moho;

gpg::RType* IAiSiloBuild::sType = nullptr;

/**
 * Address: 0x005CE850 (FUN_005CE850, ??0IAiSiloBuild@Moho@@QAE@XZ)
 * Address: 0x005CF660 (FUN_005CF660)
 *
 * What it does:
 * Initializes one silo-build interface base object; the second constructor
 * lane is an equivalent alias.
 */
IAiSiloBuild::IAiSiloBuild() = default;

/**
 * Address: 0x005CF980 (FUN_005CF980, ?AI_CreateSiloBuilder@Moho@@YAPAVIAiSiloBuild@1@PAVUnit@1@@Z)
 *
 * What it does:
 * Allocates one `CAiSiloBuildImpl` bound to `unit` and returns it through the
 * `IAiSiloBuild` interface lane.
 */
IAiSiloBuild* moho::AI_CreateSiloBuilder(Unit* const unit)
{
  auto* const impl = new (std::nothrow) CAiSiloBuildImpl(unit);
  return impl ? static_cast<IAiSiloBuild*>(impl) : nullptr;
}

/**
 * Address: 0x005CE860 (FUN_005CE860, scalar deleting thunk)
 */
IAiSiloBuild::~IAiSiloBuild() = default;
