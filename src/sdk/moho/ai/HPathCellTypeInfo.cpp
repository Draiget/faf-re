#include "moho/ai/HPathCellTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiPathFinder.h"

// HPathCell registration runs from the earliest C++ initializer segment (binary
// __xc_a) so the descriptor is preregistered before default-segment bootstrap
// objects query HPathCell RTTI during static initialization.
#pragma init_seg(lib)

namespace
{
  alignas(moho::HPathCellTypeInfo) unsigned char gHPathCellTypeInfoStorage[sizeof(moho::HPathCellTypeInfo)];
  bool gHPathCellTypeInfoConstructed = false;

  [[nodiscard]] moho::HPathCellTypeInfo* AcquireHPathCellTypeInfo()
  {
    if (!gHPathCellTypeInfoConstructed) {
      new (gHPathCellTypeInfoStorage) moho::HPathCellTypeInfo();
      gHPathCellTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::HPathCellTypeInfo*>(gHPathCellTypeInfoStorage);
  }

  /**
   * Address: 0x00C01680 (FUN_00C01680)
   *
   * What it does:
   * Runs startup-registered teardown for the global `HPathCell` descriptor,
   * releasing its reflected field/base lanes.
   */
  void cleanup_HPathCellTypeInfo()
  {
    if (!gHPathCellTypeInfoConstructed) {
      return;
    }

    AcquireHPathCellTypeInfo()->~HPathCellTypeInfo();
    gHPathCellTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00762E40 (FUN_00762E40, construct-and-preregister worker)
   *
   * What it does:
   * Preregisters `HPathCell` RTTI so lookup resolves to this type helper.
   */
  HPathCellTypeInfo::HPathCellTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(HPathCell), this);
  }

  /**
   * Address: 0x00762ED0 (FUN_00762ED0, scalar deleting thunk)
   */
  HPathCellTypeInfo::~HPathCellTypeInfo() = default;

  /**
   * Address: 0x00762EC0 (FUN_00762EC0)
   *
   * What it does:
   * Returns the reflection type name literal for HPathCell.
   */
  const char* HPathCellTypeInfo::GetName() const
  {
    return "HPathCell";
  }

  /**
   * Address: 0x00762EA0 (FUN_00762EA0)
   *
   * What it does:
   * Writes `size_` for HPathCell, then performs base-init/finalization.
   */
  void HPathCellTypeInfo::Init()
  {
    size_ = sizeof(HPathCell);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BDC610 (FUN_00BDC610, register_HPathCellTypeInfo)
   *
   * What it does:
   * Registers the `HPathCell` type-info object and installs process-exit cleanup.
   */
  int register_HPathCellTypeInfo()
  {
    (void)AcquireHPathCellTypeInfo();
    return std::atexit(&cleanup_HPathCellTypeInfo);
  }
} // namespace moho

namespace
{
  struct HPathCellTypeInfoRegistration
  {
    HPathCellTypeInfoRegistration()
    {
      (void)moho::register_HPathCellTypeInfo();
    }
  };

  [[maybe_unused]] HPathCellTypeInfoRegistration gHPathCellTypeInfoRegistration;
} // namespace
