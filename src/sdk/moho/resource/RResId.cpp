#include "moho/resource/RResId.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/misc/StartupHelpers.h"

#pragma init_seg(lib)

namespace
{
  using TypeInfo = moho::RResIdType;

  alignas(TypeInfo) unsigned char gRResIdTypeStorage[sizeof(TypeInfo)];
  bool gRResIdTypeConstructed = false;

  [[nodiscard]] TypeInfo& AcquireRResIdType()
  {
    if (!gRResIdTypeConstructed) {
      new (gRResIdTypeStorage) TypeInfo();
      gRResIdTypeConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gRResIdTypeStorage);
  }

  void cleanup_RResIdType_00BC5A60_Impl()
  {
    if (!gRResIdTypeConstructed) {
      return;
    }

    AcquireRResIdType().~TypeInfo();
    gRResIdTypeConstructed = false;
  }

  int register_RResIdType_00BC5A60_Impl()
  {
    (void)AcquireRResIdType();
    return std::atexit(&cleanup_RResIdType_00BC5A60_Impl);
  }

  struct RResIdTypeBootstrap
  {
    RResIdTypeBootstrap()
    {
      (void)register_RResIdType_00BC5A60_Impl();
    }
  };

  RResIdTypeBootstrap gRResIdTypeBootstrap;
} // namespace

namespace moho
{
  gpg::RType* RResId::sType = nullptr;

  gpg::RType* RResId::StaticGetClass()
  {
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(RResId));
    }
    return sType;
  }

  /**
   * Address: 0x004A9350 (FUN_004A9350, Moho::RES_CompletePath)
   */
  msvc8::string RES_CompletePath(const gpg::StrArg resourceName, const gpg::StrArg sourceName)
  {
    const msvc8::string sourceDir = FILE_DirPrefix(sourceName);
    const msvc8::string absolutePath = FILE_MakeAbsolute(resourceName, sourceDir.c_str());
    return FILE_CollapsePath(absolutePath.c_str(), nullptr);
  }

  /**
   * Address: 0x004A9490 (FUN_004A9490, Moho::RResIdType::RResIdType)
   */
  RResIdType::RResIdType()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RResId), this);
    RResId::sType = this;
  }

  /**
   * Address: 0x004A9520 (FUN_004A9520, scalar deleting destructor lane)
   * Address: 0x004A9620 (FUN_004A9620, duplicate deleting destructor lane)
   */
  RResIdType::~RResIdType() = default;

  /**
   * Address: 0x004A9510 (FUN_004A9510)
   */
  const char* RResIdType::GetName() const
  {
    return "RResId";
  }

  /**
   * Address: 0x004A9450 (FUN_004A9450, Moho::RResIdType::GetLexical)
   */
  msvc8::string RResIdType::GetLexical(const gpg::RRef& ref) const
  {
    const auto* const resourceId = static_cast<const RResId*>(ref.mObj);
    if (resourceId == nullptr) {
      return {};
    }
    return resourceId->name;
  }

  /**
   * Address: 0x004A9430 (FUN_004A9430, Moho::RResIdType::SetLexical)
   */
  bool RResIdType::SetLexical(const gpg::RRef& ref, const char* const lexical) const
  {
    auto* const resourceId = static_cast<RResId*>(ref.mObj);
    if (resourceId == nullptr) {
      return false;
    }

    resourceId->name.assign_owned(lexical != nullptr ? lexical : "");
    gpg::STR_NormalizeFilenameLowerSlash(resourceId->name);
    return true;
  }

  /**
   * Address: 0x004A94F0 (FUN_004A94F0)
   */
  void RResIdType::Init()
  {
    size_ = sizeof(RResId);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho
