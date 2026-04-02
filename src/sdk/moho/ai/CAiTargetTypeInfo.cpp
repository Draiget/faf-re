#include "moho/ai/CAiTargetTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiTarget.h"

using namespace moho;

namespace
{
  alignas(CAiTargetTypeInfo) unsigned char gCAiTargetTypeInfoStorage[sizeof(CAiTargetTypeInfo)];
  bool gCAiTargetTypeInfoConstructed = false;

  [[nodiscard]] CAiTargetTypeInfo* AcquireCAiTargetTypeInfo()
  {
    if (!gCAiTargetTypeInfoConstructed) {
      new (gCAiTargetTypeInfoStorage) CAiTargetTypeInfo();
      gCAiTargetTypeInfoConstructed = true;
    }

    return reinterpret_cast<CAiTargetTypeInfo*>(gCAiTargetTypeInfoStorage);
  }

  void cleanup_CAiTargetTypeInfo()
  {
    if (!gCAiTargetTypeInfoConstructed) {
      return;
    }

    AcquireCAiTargetTypeInfo()->~CAiTargetTypeInfo();
    gCAiTargetTypeInfoConstructed = false;
  }
} // namespace

/**
 * Address: 0x005E2570 (FUN_005E2570, scalar deleting thunk)
 */
CAiTargetTypeInfo::~CAiTargetTypeInfo() = default;

/**
 * Address: 0x005E2560 (FUN_005E2560)
 *
 * What it does:
 * Returns the reflection type name literal for CAiTarget.
 */
const char* CAiTargetTypeInfo::GetName() const
{
  return "CAiTarget";
}

/**
 * Address: 0x005E2540 (FUN_005E2540)
 *
 * What it does:
 * Writes `size_` for CAiTarget, then performs base-init/finalization.
 */
void CAiTargetTypeInfo::Init()
{
  size_ = sizeof(CAiTarget);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BCEC30 (FUN_00BCEC30, register_CAiTargetTypeInfo)
 *
 * What it does:
 * Registers `CAiTarget` type-info object and installs process-exit cleanup.
 */
int moho::register_CAiTargetTypeInfo()
{
  auto* const type = AcquireCAiTargetTypeInfo();
  gpg::PreRegisterRType(typeid(CAiTarget), type);
  CAiTarget::sType = type;
  return std::atexit(&cleanup_CAiTargetTypeInfo);
}
