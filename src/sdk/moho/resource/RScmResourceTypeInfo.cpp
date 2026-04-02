#include "moho/resource/RScmResourceTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/resource/RScmResource.h"

#pragma init_seg(lib)

namespace
{
  using TypeInfo = moho::RScmResourceTypeInfo;

  alignas(TypeInfo) unsigned char gRScmResourceTypeInfoStorage[sizeof(TypeInfo)];
  bool gRScmResourceTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireRScmResourceTypeInfo()
  {
    if (!gRScmResourceTypeInfoConstructed) {
      new (gRScmResourceTypeInfoStorage) TypeInfo();
      gRScmResourceTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gRScmResourceTypeInfoStorage);
  }

  void cleanup_RScmResourceTypeInfo()
  {
    if (!gRScmResourceTypeInfoConstructed) {
      return;
    }

    AcquireRScmResourceTypeInfo().~TypeInfo();
    gRScmResourceTypeInfoConstructed = false;
  }

  struct RScmResourceTypeInfoBootstrap
  {
    RScmResourceTypeInfoBootstrap()
    {
      moho::register_RScmResourceTypeInfo();
    }
  };

  RScmResourceTypeInfoBootstrap gRScmResourceTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00538AB0 (FUN_00538AB0, Moho::RScmResourceTypeInfo::RScmResourceTypeInfo)
   */
  RScmResourceTypeInfo::RScmResourceTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RScmResource), this);
  }

  /**
   * Address: 0x00538B40 (FUN_00538B40, Moho::RScmResourceTypeInfo::dtr)
   */
  RScmResourceTypeInfo::~RScmResourceTypeInfo() = default;

  /**
   * Address: 0x00538B30 (FUN_00538B30, Moho::RScmResourceTypeInfo::GetName)
   */
  const char* RScmResourceTypeInfo::GetName() const
  {
    return "RScmResource";
  }

  /**
   * Address: 0x00538B10 (FUN_00538B10, Moho::RScmResourceTypeInfo::Init)
   *
   * What it does:
   * Initializes reflection metadata for `RScmResource`
   * (`binary object size = 0x4C`) and finalizes indices.
   */
  void RScmResourceTypeInfo::Init()
  {
    size_ = 0x4C;
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BC90F0 (FUN_00BC90F0, register_RScmResourceTypeInfo)
   */
  void register_RScmResourceTypeInfo()
  {
    (void)AcquireRScmResourceTypeInfo();
    (void)std::atexit(&cleanup_RScmResourceTypeInfo);
  }
} // namespace moho
