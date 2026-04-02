#include "moho/ai/CAiSiloBuildImplTypeInfo.h"

#include <cstdlib>
#include <list>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiSiloBuildImpl.h"
#include "moho/ai/CAiSiloBuildImplConstruct.h"
#include "moho/ai/CAiSiloBuildImplSerializer.h"

using namespace moho;

namespace
{
  class SSiloBuildInfoTypeInfo final : public gpg::RType
  {
  public:
    ~SSiloBuildInfoTypeInfo() override;
    [[nodiscard]] const char* GetName() const override;
    void Init() override;
  };

  class ESiloTypeListTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "list<ESiloType>";
    }
  };

  static_assert(sizeof(SSiloBuildInfoTypeInfo) == 0x64, "SSiloBuildInfoTypeInfo size must be 0x64");
  static_assert(sizeof(ESiloTypeListTypeInfo) == 0x64, "ESiloTypeListTypeInfo size must be 0x64");

  alignas(SSiloBuildInfoTypeInfo) unsigned char gSSiloBuildInfoTypeInfoStorage[sizeof(SSiloBuildInfoTypeInfo)];
  bool gSSiloBuildInfoTypeInfoConstructed = false;

  alignas(CAiSiloBuildImplTypeInfo) unsigned char gCAiSiloBuildImplTypeInfoStorage[sizeof(CAiSiloBuildImplTypeInfo)];
  bool gCAiSiloBuildImplTypeInfoConstructed = false;

  alignas(ESiloTypeListTypeInfo) unsigned char gESiloTypeListTypeInfoStorage[sizeof(ESiloTypeListTypeInfo)];
  bool gESiloTypeListTypeInfoConstructed = false;

  [[nodiscard]] SSiloBuildInfoTypeInfo* AcquireSSiloBuildInfoTypeInfo()
  {
    if (!gSSiloBuildInfoTypeInfoConstructed) {
      auto* const typeInfo = new (gSSiloBuildInfoTypeInfoStorage) SSiloBuildInfoTypeInfo();
      gpg::PreRegisterRType(typeid(SSiloBuildInfo), typeInfo);
      SSiloBuildInfo::sType = typeInfo;
      gSSiloBuildInfoTypeInfoConstructed = true;
    }

    return reinterpret_cast<SSiloBuildInfoTypeInfo*>(gSSiloBuildInfoTypeInfoStorage);
  }

  [[nodiscard]] CAiSiloBuildImplTypeInfo* AcquireCAiSiloBuildImplTypeInfo()
  {
    if (!gCAiSiloBuildImplTypeInfoConstructed) {
      auto* const typeInfo = new (gCAiSiloBuildImplTypeInfoStorage) CAiSiloBuildImplTypeInfo();
      gpg::PreRegisterRType(typeid(CAiSiloBuildImpl), typeInfo);
      gCAiSiloBuildImplTypeInfoConstructed = true;
    }

    return reinterpret_cast<CAiSiloBuildImplTypeInfo*>(gCAiSiloBuildImplTypeInfoStorage);
  }

  [[nodiscard]] ESiloTypeListTypeInfo* AcquireESiloTypeListTypeInfo()
  {
    if (!gESiloTypeListTypeInfoConstructed) {
      auto* const typeInfo = new (gESiloTypeListTypeInfoStorage) ESiloTypeListTypeInfo();
      gpg::PreRegisterRType(typeid(std::list<ESiloType>), typeInfo);
      gESiloTypeListTypeInfoConstructed = true;
    }

    return reinterpret_cast<ESiloTypeListTypeInfo*>(gESiloTypeListTypeInfoStorage);
  }

  /**
   * Address: 0x005CEB30 (FUN_005CEB30, preregister_SSiloBuildInfoTypeInfo)
   *
   * What it does:
   * Constructs and preregisters static `SSiloBuildInfoTypeInfo` storage.
   */
  [[nodiscard]] gpg::RType* preregister_SSiloBuildInfoTypeInfo()
  {
    return AcquireSSiloBuildInfoTypeInfo();
  }

  /**
   * Address: 0x005CF670 (FUN_005CF670, sub_5CF670)
   *
   * What it does:
   * Constructs and preregisters static `CAiSiloBuildImplTypeInfo` storage.
   */
  [[nodiscard]] gpg::RType* preregister_CAiSiloBuildImplTypeInfo()
  {
    return AcquireCAiSiloBuildImplTypeInfo();
  }

  /**
   * Address: 0x005D0B00 (FUN_005D0B00, sub_5D0B00)
   *
   * What it does:
   * Constructs and preregisters reflected `std::list<ESiloType>` type-info.
   */
  [[nodiscard]] gpg::RType* preregister_ESiloTypeListTypeInfo()
  {
    return AcquireESiloTypeListTypeInfo();
  }

  [[nodiscard]] gpg::RType* CachedIAiSiloBuildType()
  {
    if (!IAiSiloBuild::sType) {
      IAiSiloBuild::sType = gpg::LookupRType(typeid(IAiSiloBuild));
    }
    return IAiSiloBuild::sType;
  }

  /**
   * Address: 0x00BF7ED0 (FUN_00BF7ED0, cleanup_CAiSiloBuildImplTypeInfo)
   *
   * What it does:
   * Tears down static `CAiSiloBuildImplTypeInfo` storage at process exit.
   */
  void cleanup_CAiSiloBuildImplTypeInfo()
  {
    if (!gCAiSiloBuildImplTypeInfoConstructed) {
      return;
    }

    AcquireCAiSiloBuildImplTypeInfo()->~CAiSiloBuildImplTypeInfo();
    gCAiSiloBuildImplTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BF7E40 (FUN_00BF7E40, cleanup_SSiloBuildInfoTypeInfo)
   *
   * What it does:
   * Tears down static `SSiloBuildInfoTypeInfo` storage at process exit.
   */
  void cleanup_SSiloBuildInfoTypeInfo()
  {
    if (!gSSiloBuildInfoTypeInfoConstructed) {
      return;
    }

    AcquireSSiloBuildInfoTypeInfo()->~SSiloBuildInfoTypeInfo();
    SSiloBuildInfo::sType = nullptr;
    gSSiloBuildInfoTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BF7FC0 (FUN_00BF7FC0, cleanup_ESiloTypeListTypeInfo)
   *
   * What it does:
   * Tears down static reflected `std::list<ESiloType>` type-info storage.
   */
  void cleanup_ESiloTypeListTypeInfo()
  {
    if (!gESiloTypeListTypeInfoConstructed) {
      return;
    }

    AcquireESiloTypeListTypeInfo()->~ESiloTypeListTypeInfo();
    gESiloTypeListTypeInfoConstructed = false;
  }
} // namespace

/**
 * Address: 0x005CEBC0 (FUN_005CEBC0, scalar deleting thunk)
 */
SSiloBuildInfoTypeInfo::~SSiloBuildInfoTypeInfo() = default;

/**
 * Address: 0x005CEBB0 (FUN_005CEBB0, Moho::SSiloBuildInfoTypeInfo::GetName)
 */
const char* SSiloBuildInfoTypeInfo::GetName() const
{
  return "SSiloBuildInfo";
}

/**
 * Address: 0x005CEB90 (FUN_005CEB90, Moho::SSiloBuildInfoTypeInfo::Init)
 */
void SSiloBuildInfoTypeInfo::Init()
{
  size_ = sizeof(SSiloBuildInfo);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x005CF700 (FUN_005CF700, scalar deleting thunk)
 */
CAiSiloBuildImplTypeInfo::~CAiSiloBuildImplTypeInfo() = default;

/**
 * Address: 0x005CF6F0 (FUN_005CF6F0, ?GetName@CAiSiloBuildImplTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiSiloBuildImplTypeInfo::GetName() const
{
  return "CAiSiloBuildImpl";
}

/**
 * Address: 0x005CF6D0 (FUN_005CF6D0, ?Init@CAiSiloBuildImplTypeInfo@Moho@@UAEXXZ)
 */
void CAiSiloBuildImplTypeInfo::Init()
{
  size_ = sizeof(CAiSiloBuildImpl);
  gpg::RType::Init();

  gpg::RType* const baseType = CachedIAiSiloBuildType();
  if (baseType) {
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    AddBase(baseField);
  }

  Finish();
}

/**
 * Address: 0x00BCE090 (FUN_00BCE090, register_SSiloBuildInfoTypeInfo)
 *
 * What it does:
 * Registers `SSiloBuildInfo` RTTI type-info and installs process-exit
 * cleanup for its static storage.
 */
int moho::register_SSiloBuildInfoTypeInfo()
{
  (void)preregister_SSiloBuildInfoTypeInfo();
  return std::atexit(&cleanup_SSiloBuildInfoTypeInfo);
}

/**
 * Address: 0x00BCE0F0 (FUN_00BCE0F0, register_CAiSiloBuildImplTypeInfo)
 *
 * What it does:
 * Registers `CAiSiloBuildImpl` RTTI type-info and installs process-exit
 * cleanup for its static storage.
 */
int moho::register_CAiSiloBuildImplTypeInfo()
{
  (void)preregister_CAiSiloBuildImplTypeInfo();
  return std::atexit(&cleanup_CAiSiloBuildImplTypeInfo);
}

/**
 * Address: 0x00BCE190 (FUN_00BCE190, register_ESiloTypeListTypeInfo)
 *
 * What it does:
 * Registers reflected `std::list<ESiloType>` type-info and installs
 * process-exit cleanup for its static storage.
 */
int moho::register_ESiloTypeListTypeInfo()
{
  (void)preregister_ESiloTypeListTypeInfo();
  return std::atexit(&cleanup_ESiloTypeListTypeInfo);
}

namespace
{
  struct CAiSiloBuildTypeInfoBootstrap
  {
    CAiSiloBuildTypeInfoBootstrap()
    {
      (void)moho::register_SSiloBuildInfoTypeInfo();
      (void)moho::register_SSiloBuildInfoSerializer();
      (void)moho::register_CAiSiloBuildImplTypeInfo();
      (void)moho::register_CAiSiloBuildImplConstruct();
      (void)moho::register_CAiSiloBuildImplSerializer();
      (void)moho::register_ESiloTypeListTypeInfo();
    }
  };

  [[maybe_unused]] CAiSiloBuildTypeInfoBootstrap gCAiSiloBuildTypeInfoBootstrap;
} // namespace
