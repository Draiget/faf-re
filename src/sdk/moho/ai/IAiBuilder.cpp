#include "moho/ai/IAiBuilder.h"

#include <new>

#include "moho/ai/CAiBuilderImpl.h"

using namespace moho;

gpg::RType* IAiBuilder::sType = nullptr;

/**
 * Address: 0x0059ED60 (FUN_0059ED60, ??0IAiBuilder@Moho@@QAE@XZ)
 *
 * What it does:
 * Initializes the IAiBuilder interface base lane for derived builders.
 */
IAiBuilder::IAiBuilder() = default;

/**
 * Address: 0x0059FB70 (FUN_0059FB70)
 *
 * What it does:
 * Alternate in-place constructor adapter lane for one IAiBuilder interface
 * subobject.
 */
[[maybe_unused]] IAiBuilder* InitializeIAiBuilderInterfaceLane(IAiBuilder* const objectStorage) noexcept
{
  return objectStorage;
}

/**
 * Address: 0x0059ED70 (FUN_0059ED70, scalar deleting thunk)
 */
IAiBuilder::~IAiBuilder() = default;

/**
 * Address: 0x0059FED0 (FUN_0059FED0, ?AI_CreateBuilder@Moho@@YAPAVIAiBuilder@1@PAVUnit@1@@Z)
 *
 * What it does:
 * Allocates one `CAiBuilderImpl` for `unit` and returns it as the
 * `IAiBuilder` interface pointer.
 */
IAiBuilder* moho::AI_CreateBuilder(Unit* const unit)
{
  auto* const builder = new (std::nothrow) CAiBuilderImpl(unit);
  return builder;
}
