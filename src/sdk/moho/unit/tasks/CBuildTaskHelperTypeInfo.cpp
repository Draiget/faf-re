#include "moho/unit/tasks/CBuildTaskHelperTypeInfo.h"

#include <cstdlib>
#include <typeinfo>

#include "moho/unit/tasks/CBuildTaskHelper.h"

namespace
{
  using TypeInfo = moho::CBuildTaskHelperTypeInfo;

  alignas(TypeInfo) unsigned char gTypeInfoStorage[sizeof(TypeInfo)];
  bool gTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireTypeInfo()
  {
    if (!gTypeInfoConstructed) {
      new (gTypeInfoStorage) TypeInfo();
      gTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gTypeInfoStorage);
  }

  void cleanup()
  {
    if (!gTypeInfoConstructed) {
      return;
    }

    AcquireTypeInfo().~CBuildTaskHelperTypeInfo();
    gTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005F5820 (FUN_005F5820, ??0CBuildTaskHelperTypeInfo@Moho@@QAE@@Z)
   *
   * What it does:
   * Preregisters `CBuildTaskHelper` RTTI into the reflection lookup table.
   */
  CBuildTaskHelperTypeInfo::CBuildTaskHelperTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CBuildTaskHelper), this);
  }

  /**
   * Address: 0x005F58B0 (FUN_005F58B0, scalar deleting thunk)
   */
  CBuildTaskHelperTypeInfo::~CBuildTaskHelperTypeInfo() = default;

  /**
   * Address: 0x005F58A0 (FUN_005F58A0)
   */
  const char* CBuildTaskHelperTypeInfo::GetName() const
  {
    return "CBuildTaskHelper";
  }

  /**
   * Address: 0x005F5880 (FUN_005F5880)
   *
   * What it does:
   * Sets the reflected size (0x44) and finalizes metadata. No allocator
   * callbacks — CBuildTaskHelper is not independently constructable via
   * the reflection system.
   */
  void CBuildTaskHelperTypeInfo::Init()
  {
    size_ = 0x44;
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BCF810 (FUN_00BCF810, register_CBuildTaskHelperTypeInfo)
   */
  int register_CBuildTaskHelperTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup);
  }
} // namespace moho
