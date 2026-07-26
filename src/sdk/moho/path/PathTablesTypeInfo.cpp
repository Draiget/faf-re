#include "moho/path/PathTablesTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/path/PathTables.h"

// PathTables registration runs from the earliest C++ initializer segment (binary
// __xc_a) so the descriptor is preregistered before default-segment bootstrap
// objects query PathTables RTTI during static initialization.
#pragma init_seg(lib)

namespace
{
  alignas(moho::PathTablesTypeInfo) unsigned char gPathTablesTypeInfoStorage[sizeof(moho::PathTablesTypeInfo)];
  bool gPathTablesTypeInfoConstructed = false;

  [[nodiscard]] moho::PathTablesTypeInfo* AcquirePathTablesTypeInfo()
  {
    if (!gPathTablesTypeInfoConstructed) {
      new (gPathTablesTypeInfoStorage) moho::PathTablesTypeInfo();
      gPathTablesTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::PathTablesTypeInfo*>(gPathTablesTypeInfoStorage);
  }

  /**
   * Address: 0x00C01C20 (FUN_00C01C20)
   *
   * What it does:
   * Runs startup-registered teardown for the global `PathTables` descriptor,
   * releasing its reflected field/base lanes.
   */
  void cleanup_PathTablesTypeInfo()
  {
    if (!gPathTablesTypeInfoConstructed) {
      return;
    }

    AcquirePathTablesTypeInfo()->~PathTablesTypeInfo();
    gPathTablesTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0076BDB0 (FUN_0076BDB0, construct-and-preregister worker)
   *
   * What it does:
   * Preregisters `PathTables` RTTI so lookup resolves to this type helper.
   */
  PathTablesTypeInfo::PathTablesTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(PathTables), this);
  }

  /**
   * Address: 0x0076BE40 (FUN_0076BE40, scalar deleting thunk)
   */
  PathTablesTypeInfo::~PathTablesTypeInfo() = default;

  /**
   * Address: 0x0076BE30 (FUN_0076BE30)
   *
   * What it does:
   * Returns the reflection type name literal for PathTables.
   */
  const char* PathTablesTypeInfo::GetName() const
  {
    return "PathTables";
  }

  /**
   * Address: 0x0076BE10 (FUN_0076BE10)
   *
   * What it does:
   * Writes `size_` for PathTables, then performs base-init/finalization.
   */
  void PathTablesTypeInfo::Init()
  {
    size_ = sizeof(PathTables);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BDCA50 (FUN_00BDCA50, register_PathTablesTypeInfo)
   *
   * What it does:
   * Registers the `PathTables` type-info object and installs process-exit cleanup.
   */
  int register_PathTablesTypeInfo()
  {
    (void)AcquirePathTablesTypeInfo();
    return std::atexit(&cleanup_PathTablesTypeInfo);
  }
} // namespace moho

namespace
{
  struct PathTablesTypeInfoRegistration
  {
    PathTablesTypeInfoRegistration()
    {
      (void)moho::register_PathTablesTypeInfo();
    }
  };

  [[maybe_unused]] PathTablesTypeInfoRegistration gPathTablesTypeInfoRegistration;
} // namespace
